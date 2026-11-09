"""Offline, content-bound G1/G2/G3 construction and deterministic E1 pilot.

Collection executes separately; this module never runs project code or a resolver.
"""
from __future__ import annotations

from datetime import datetime, timezone
import configparser
import ast
import email
import hashlib
import json
import random
import tarfile
import tomllib
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

from packaging.requirements import Requirement, InvalidRequirement
from packaging.utils import canonicalize_name
from packageurl import PackageURL

from sbom_recovery.core.canonical import EvidenceItem, VerificationRecord
from .gold_contracts import CaseManifest, ClaimV2, LedgerV2, contained, fingerprint
from sbom_recovery.evidence.storage import save
from .proof import locator as proof_locator, pointer


def purl(ecosystem, name, version=None):
    if ecosystem == "maven":
        namespace, name = name.split(":", 1)
    elif ecosystem == "npm" and name.startswith("@"):
        namespace, name = name.split("/", 1)
    else:
        namespace = None
        if ecosystem == "pypi": name = canonicalize_name(name)
    return PackageURL(type=ecosystem, namespace=namespace, name=name, version=version).to_string()


class Builder:
    def __init__(self, case_path, allowed_only=False):
        self.root = Path(case_path).resolve().parent
        self.case = CaseManifest.model_validate_json(Path(case_path).read_text())
        self.allowed_only = allowed_only
        self.case.verify_files(self.root,self.case.allowed_evidence if allowed_only else None)
        self.gold = LedgerV2(case_id=self.case.case_id, case_manifest_sha256=self.case.digest(), role="gold")
        self.issues = []

    def emit(self, source, instance, subject, predicate, obj, layer, scope="runtime_production",
             locator="", condition=None, status="verified"):
        item = self.case.files[source]
        kind = {"manifest": "manifest_source", "resolver": "native_resolver_report",
                "artifact": "installed_artifact_metadata"}[item.kind]
        self.gold.add_claim(ClaimV2(case_id=self.case.case_id, target_id=self.case.target,
            instance_id=instance, subject=subject, predicate=predicate, object=obj, layer=layer,
            scope=scope, condition=condition, status=status, role="gold",
            evidence=[EvidenceItem(source_id=source, source_type=kind, artifact_sha256=item.sha256,
                                   locator=locator, raw_value=obj)],
            verification=VerificationRecord(method="direct_artifact_inspection" if layer=="G3_artifact"
                                             else "deterministic_parser", review_status="accepted")))

    def manifest(self, source):
        item = self.case.files[source]
        path = contained(self.root, item.path)
        root = "urn:target:" + self.case.case_id + ":" + self.case.target
        emit = lambda pred,obj,**kw: self.emit(source,"root",root,pred,obj,"G1_source",**kw)
        if path.name == "pyproject.toml":
            data = tomllib.loads(path.read_text())
            project = data.get("project", {})
            poetry = data.get("tool", {}).get("poetry", {})
            for pred in ("name", "version"):
                val = project.get(pred) or poetry.get(pred)
                if val: emit(pred,str(val),locator=proof_locator("toml", pointer(*(["project",pred] if project.get(pred) else ["tool","poetry",pred]))))
            license_value = project.get("license") or poetry.get("license")
            if isinstance(license_value,str): emit("licenseDeclared",license_value,locator=proof_locator("toml", pointer(*(["project","license"] if project.get("license") else ["tool","poetry","license"]))))
            for index,dep in enumerate(project.get("dependencies", [])): self.requirement(source,root,dep,proof_locator("toml",pointer("project","dependencies",index),"python-requirement"))
            for extra,deps in project.get("optional-dependencies",{}).items():
                for index,dep in enumerate(deps): self.requirement(source,root,dep,proof_locator("toml",pointer("project","optional-dependencies",extra,index),"python-requirement"),extra)
            for name,req in poetry.get("dependencies",{}).items():
                if name == "python": continue
                optional = isinstance(req,dict) and req.get("optional",False)
                emit("depends_on",{"package":purl("pypi",name),"poetry_declaration":req},
                     scope="optional" if optional else "runtime_production",locator=proof_locator("toml",pointer("tool","poetry","dependencies",name),"poetry-requirement"))
            if project.get("dynamic"): self.issues.append({"source":source,"status":"UNKNOWN","dynamic":project["dynamic"]})
        elif path.name == "setup.py":
            # Literal declarations only. Never import or execute setup.py.
            tree = ast.parse(path.read_text())
            literals = {}
            for node in tree.body:
                if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
                    try: literals[node.targets[0].id]=ast.literal_eval(node.value)
                    except (ValueError,TypeError): literals.pop(node.targets[0].id,None)
                if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name) and node.value.func.id=="setup":
                    for kw in node.value.keywords:
                        try: val=literals[kw.value.id] if isinstance(kw.value,ast.Name) else ast.literal_eval(kw.value)
                        except (ValueError,TypeError,KeyError):
                            if kw.arg in {"name","version","install_requires"}: self.issues.append({"source":source,"status":"UNKNOWN","dynamic":kw.arg})
                            continue
                        if kw.arg in {"name","version"} and isinstance(val,str): emit(kw.arg,val,locator=proof_locator("setup",pointer("setup",kw.arg)))
                        elif kw.arg=="install_requires" and isinstance(val,list):
                            for index,dep in enumerate(val): self.requirement(source,root,dep,proof_locator("setup",pointer("setup","install_requires",index),"python-requirement"))
        elif path.name == "setup.cfg":
            cfg = configparser.ConfigParser(interpolation=None)
            cfg.read_string(path.read_text())
            for pred in ("name","version"):
                val = cfg.get("metadata",pred,fallback=None)
                if val and not val.startswith(("attr:","file:")): emit(pred,val,locator=proof_locator("ini",pointer("metadata",pred)))
            for index,dep in enumerate(x.strip() for x in cfg.get("options","install_requires",fallback="").splitlines() if x.strip()):
                self.requirement(source,root,dep,proof_locator("ini",pointer("options","install_requires",index),"python-requirement"))
        elif path.name == "package.json":
            data = json.loads(path.read_text())
            for pred in ("name","version","license"):
                if data.get(pred): emit("licenseDeclared" if pred=="license" else pred,data[pred],locator=proof_locator("json",pointer(pred)))
            for field,scope in [("dependencies","runtime_production"),("devDependencies","development"),
                                ("optionalDependencies","optional"),("peerDependencies","optional")]:
                for name,req in data.get(field,{}).items():
                    emit("depends_on",{"package":purl("npm",name),"requirement":req},
                         scope=scope,locator=proof_locator("json",pointer(field,name),"npm-requirement"))
        elif path.name == "pom.xml":
            tree = ET.fromstring(path.read_text())
            for node in tree.iter(): node.tag = node.tag.split("}")[-1]
            parent = tree.find("parent")
            gid = tree.findtext("groupId") or (parent.findtext("groupId") if parent is not None else None)
            aid = tree.findtext("artifactId")
            ver = tree.findtext("version") or (parent.findtext("version") if parent is not None else None)
            if gid and aid: emit("name",gid+":"+aid,locator=proof_locator("pom","","maven-name"))
            if ver and "${" not in ver: emit("version",ver,locator=proof_locator("pom",pointer("version") if tree.findtext("version") else pointer("parent","version")))
            for index,dep in enumerate(tree.findall("dependencies/dependency")):
                gid,aid = dep.findtext("groupId"),dep.findtext("artifactId")
                if not gid or not aid: continue
                declared_scope = dep.findtext("scope","compile")
                scope = {"test":"test","provided":"build","system":"build"}.get(declared_scope,"runtime_production")
                emit("depends_on",{"package":purl("maven",gid+":"+aid),"requirement":dep.findtext("version"),
                                   "maven_scope":declared_scope}, scope=scope,locator=proof_locator("pom",pointer("dependencies",index),"maven-requirement"))
        else:
            # Gradle scripts are executable programs: lexical parsing does not produce verified declarations.
            self.issues.append({"source":source,"status":"UNKNOWN","reason":"Native effective model required for executable/dynamic manifest"})

    def requirement(self, source, root, raw, locator, extra=None):
        try:
            req = Requirement(raw)
            self.emit(source,"root",root,"depends_on",{"package":purl("pypi",req.name),
                "requirement":str(req.specifier),"extras":sorted(req.extras),"url":req.url},"G1_source",
                scope="optional" if extra else "runtime_production",locator=locator,
                condition="; ".join(x for x in [str(req.marker) if req.marker else None,
                                                "extra == " + repr(extra) if extra else None] if x) or None)
        except InvalidRequirement:
            self.issues.append({"source":source,"status":"UNKNOWN","reason":"Unparsed requirement","value":raw})

    def resolved(self, source):
        data = json.loads(contained(self.root,self.case.files[source].path).read_text())
        if "status" not in data:
            return  # Raw supporting native report, interpreted through its bound envelope.
        if self.case.resolution_status != "COMPLETE" or data.get("status") != "COMPLETE":
            self.issues.append({"source":source,"status":"UNKNOWN","reason":"Resolution incomplete"})
            return
        if data.get("commit") != self.case.commit or data.get("target") != self.case.target or data.get("environment") != self.case.environment:
            raise ValueError("Resolver report context does not match case")
        from sbom_recovery.reconciliation.native_graph import normalize
        raw_id = data.get("raw_evidence_id")
        if not raw_id or raw_id not in self.case.files or self.case.files[raw_id].kind != "resolver":
            raise ValueError("Raw native report binding required")
        if self.allowed_only and raw_id not in self.case.allowed_evidence:
            self.issues.append({"source":source,"status":"UNKNOWN","reason":"Raw native report not permitted"})
            return
        raw = json.loads(contained(self.root,self.case.files[raw_id].path).read_text())
        nodes, edges = normalize(self.case.ecosystem, raw, data["root_name"])
        if fingerprint([nodes,edges]) != fingerprint([data["nodes"],data["edges"]]):
            raise ValueError("Normalized report differs from native report")
        if raw.get("source_model"):
            for pred in ("name", "version"):
                obj = raw["source_model"].get(pred)
                if obj and obj != "unspecified":
                    self.emit(raw_id,"root","urn:target:"+self.case.case_id+":"+self.case.target,
                              pred,obj,"G1_source",locator=proof_locator("json",pointer("source_model",pred)))
        ids = {n["id"] for n in nodes}
        if len(ids) != len(nodes) or any(a not in ids or b not in ids for a,b in edges):
            raise ValueError("Invalid native graph endpoints or duplicate instances")
        for index,node in enumerate(nodes):
            if not node.get("version") or node["version"] in {"unspecified","unknown"}:
                self.issues.append({"source":source,"status":"UNKNOWN","reason":"Unversioned resolved node","instance":node["id"]})
                continue
            identity = purl(self.case.ecosystem,node["name"],node["version"])
            for pred,obj in [("name",node["name"]),("version",node["version"]),("purl",identity)]:
                self.emit(source,node["id"],identity,pred,obj,"G2_resolved",locator=proof_locator("json",pointer("nodes",index),"node-"+pred))
        by_id = {n["id"]:n for n in nodes}
        for index,(a,b) in enumerate(edges):
            n = by_id[a]
            if not n.get("version") or n["version"] in {"unspecified","unknown"}: continue
            self.emit(source,a,purl(self.case.ecosystem,n["name"],n["version"]),"depends_on",b,"G2_resolved",locator=proof_locator("json",pointer("edges",index),"edge"))

    def artifact(self, source):
        path = contained(self.root,self.case.files[source].path)
        if path.suffix == ".whl":
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    if info.filename.endswith(".dist-info/METADATA") and info.file_size < 2_000_000:
                        meta = email.message_from_bytes(archive.read(info))
                        name,ver = meta.get("Name"),meta.get("Version")
                        if name and ver:
                            identity = purl("pypi",name,ver)
                            for pred,obj in [("name",canonicalize_name(name)),("version",ver),("checksum",self.case.files[source].sha256)]:
                                self.emit(source,"artifact:"+source,identity,pred,obj,"G3_artifact",locator=proof_locator("wheel", "" if pred=="checksum" else pointer("Name" if pred=="name" else "Version"), "checksum" if pred=="checksum" else "python-name" if pred=="name" else "literal", info.filename))
                            if meta.get("License-Expression"):
                                self.emit(source,"artifact:"+source,identity,"licenseDeclared",meta["License-Expression"],
                                          "G3_artifact",locator=proof_locator("wheel",pointer("License-Expression"),member=info.filename))
        elif path.name.endswith((".tgz",".tar.gz")) and self.case.ecosystem == "npm":
            with tarfile.open(path) as archive:
                for member in archive.getmembers():
                    if member.name == "package/package.json" and member.isfile() and member.size < 2_000_000:
                        meta = json.load(archive.extractfile(member))
                        identity = purl("npm",meta["name"],meta["version"])
                        for pred in ("name","version","license"):
                            if meta.get(pred): self.emit(source,"artifact:"+source,identity,"licenseDeclared" if pred=="license" else pred,
                                meta[pred],"G3_artifact",locator=proof_locator("npm-tar",pointer(pred),member=member.name))
        elif path.suffix == ".jar":
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    if info.filename.endswith("/pom.properties") and info.file_size < 65536:
                        props = dict(line.split("=",1) for line in archive.read(info).decode().splitlines() if "=" in line and not line.startswith("#"))
                        if all(props.get(k) for k in ("groupId","artifactId","version")):
                            name = props["groupId"]+":"+props["artifactId"]
                            identity = purl("maven",name,props["version"])
                            for pred,obj in [("name",name),("version",props["version"])]:
                                self.emit(source,"artifact:"+source+":"+info.filename,identity,pred,obj,"G3_artifact",locator=proof_locator("jar","" if pred=="name" else pointer("version"),"jar-name" if pred=="name" else "literal",info.filename))

    def build(self):
        for source,item in self.case.files.items():
            if self.allowed_only and source not in self.case.allowed_evidence: continue
            if item.kind == "manifest": self.manifest(source)
            elif item.kind == "resolver": self.resolved(source)
            elif item.kind == "artifact": self.artifact(source)
        for claims in self.gold.find_conflicts().values():
            self.issues.append({"status":"UNKNOWN","reason":"Conflicting native declarations",
                                "claim_ids":[c.claim_id for c in claims]})
            for c in claims:
                c.status = "unknown"
                c.verification.review_status = "unresolved"
        return self.gold


def validate_gold(case_path, ledger):
    builder = Builder(case_path)
    if ledger.role != "gold" or ledger.case_id != builder.case.case_id or ledger.case_manifest_sha256 != builder.case.digest():
        raise ValueError("Gold binding mismatch")
    # Reconstruct machine proof; arbitrary plausible locators do not constitute verification.
    expected = builder.build()
    expected_claims = {c.claim_id: c for c in expected.claims}
    for c in ledger.claims:
        proof = expected_claims.get(c.claim_id)
        if not proof or c.model_dump(mode="json") != proof.model_dump(mode="json"):
            raise ValueError("Claim lacks reproducible native proof")
    if {c.claim_id for c in ledger.claims} != set(expected_claims):
        raise ValueError("Gold omits extracted claims; use explicit unknowns instead")
    from .proof import ProofReader
    provenance = ProofReader(case_path).audit(ledger)
    if provenance["status"] != "PASSED":
        raise ValueError("Independent provenance check failed: " + str(provenance["failures"][:3]))
    return {"status":"PASSED", "provenance":provenance, "claims":len(ledger.claims),"case_manifest_sha256":builder.case.digest(),
            "layers":dict(Counter(c.layer for c in ledger.claims)),"issues":builder.issues,
            "human_review":"PENDING", "calibration":"UNMEASURED"}


def build_gold(case_path, out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    builder = Builder(case_path)
    ledger = builder.build()
    ledger.save(out/"canonical.json")
    validation = validate_gold(case_path,ledger)
    save(out/"validation.json",validation)
    claims = sorted(ledger.claims,key=lambda c:c.claim_id)
    rng = random.Random(42)
    strata = {}
    for c in claims: strata.setdefault((c.layer,c.predicate),[]).append(c)
    audit = [c for key in sorted(strata) for c in rng.sample(strata[key],(len(strata[key])+4)//5)]
    save(out/"annotation-queue.json",{"status":"PENDING_INDEPENDENT_REVIEW","seed":42,
        "sampling_unit":"claim; 20% rounded up within layer/predicate strata",
        "conflict_claim_ids":[c.claim_id for cs in ledger.find_conflicts().values() for c in cs],
        "random_audit_claim_ids":[c.claim_id for c in audit],"unresolved":builder.issues,
        "agreement":"UNMEASURED","decisions":[]})
    export_gold(ledger,out)
    return validation


def export_gold(ledger,out):
    from sbom_recovery.core.formats import validate_native
    nodes = {}
    for c in ledger.claims:
        if c.layer == "G2_resolved" and c.status == "verified" and c.predicate in {"name","version","purl"}:
            nodes.setdefault(c.instance_id,{})[c.predicate] = c.object
    refs = {k:"SPDXRef-"+fingerprint(k)[:24] for k in nodes}
    if not nodes:
        save(Path(out)/"native-validation.json", {"status":"NOT_APPLICABLE", "reason":"No verified resolved inventory; G1 remains in canonical gold"})
        return
    edges = [(c.instance_id,c.object) for c in ledger.claims if c.layer=="G2_resolved" and c.predicate=="depends_on" and c.status=="verified"]
    spdx = {"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT",
        "name":ledger.case_id,"documentNamespace":"https://sbom.invalid/gold/"+ledger.fingerprint(),
        "creationInfo":{"created":datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),"creators":["Tool: evidence-gold-v2"]},
        "packages":[{"SPDXID":refs[k],"name":v["name"],"versionInfo":v["version"],"downloadLocation":"NOASSERTION",
            "filesAnalyzed":False,"licenseConcluded":"NOASSERTION","licenseDeclared":"NOASSERTION","copyrightText":"NOASSERTION",
            "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":v["purl"]}]}
            for k,v in nodes.items()],
        "relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":ref} for ref in refs.values()] +
                        [{"spdxElementId":refs[a],"relationshipType":"DEPENDS_ON","relatedSpdxElement":refs[b]}
                         for a,b in edges if a in refs and b in refs]}
    cdx = {"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
        "components":[{"type":"library","bom-ref":k,"name":v["name"],"version":v["version"],"purl":v["purl"]} for k,v in nodes.items()],
        "dependencies":[{"ref":a,"dependsOn":sorted({b for src,b in edges if src==a and b in nodes})} for a in nodes]}
    results = {"spdx":validate_native(spdx),"cyclonedx":validate_native(cdx)}
    save(Path(out)/"native-validation.json",results)
    if any(not r["valid"] for r in results.values()): raise ValueError("Gold native export invalid")
    save(Path(out)/"gold.spdx.json",spdx)
    save(Path(out)/"gold.cdx.json",cdx)

"""File-bound scope matching with native labels kept in a separate evaluator.

The predictor receives a file/hash catalog and scanner observations. It never
receives the pip/npm reference reports or desired package versions.
"""
from __future__ import annotations

import base64
from collections import Counter
from copy import deepcopy
import email
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import zipfile

from packageurl import PackageURL
from packaging.utils import canonicalize_name

from sbom_recovery.gold.gold_contracts import contained, fingerprint
from sbom_recovery.evidence.storage import save


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream,"sha256").hexdigest()


def coordinates(ecosystem,name,version):
    namespace=None
    if ecosystem=="pypi": name=canonicalize_name(name)
    elif ecosystem=="npm" and name.startswith("@"): namespace,name=name.split("/",1)
    elif ecosystem=="maven": namespace,name=name.split(":",1)
    return PackageURL(type=ecosystem,namespace=namespace,name=name,version=version).to_string()


def verify_integrity(raw,integrity):
    choices=[]
    for token in integrity.split():
        algorithm,encoded=token.split("-",1)
        if algorithm in {"sha256","sha384","sha512"}: choices.append((algorithm,encoded))
    if not choices: raise ValueError("No supported strong SRI digest")
    strongest=max(choices,key=lambda x:int(x[0][3:]))[0]
    if not any(hashlib.new(algorithm,raw).digest()==base64.b64decode(encoded,validate=True)
               for algorithm,encoded in choices if algorithm==strongest):
        raise ValueError("Frozen artifact integrity mismatch")


def npm_instance(path):
    if not isinstance(path,str) or (path and (path.startswith("/") or "\\" in path or
            any(part in {"",".",".."} for part in path.split("/")))):return False
    parts=list(PurePosixPath(path).parts)
    if path=="": return True
    while parts:
        if parts.pop(0)!="node_modules" or not parts: return False
        name=parts.pop(0)
        if name.startswith("@"):
            if len(name)==1 or not parts: return False
            name=parts.pop(0)
        if not name or name.startswith(".") or name in {"..","node_modules"}: return False
    return True


def npm_snapshot(raw,issues=None):
    """Flatten explicit physical paths, not a guessed logical dependency layout."""
    root=PurePosixPath(raw["path"]);result={};visited=0
    if not root.is_absolute() or ".." in root.parts: raise ValueError("Invalid native root")
    def visit(row,fallback,depth=0):
        nonlocal visited
        visited+=1
        if len(result)>10000 or visited>100000 or depth>200: raise ValueError("Snapshot node limit")
        if row=={}:
            if issues is not None:issues.append({"name":fallback,"status":"UNKNOWN","reason":"Native dependency placeholder has no physical path or installed identity"})
            return
        path=PurePosixPath(row["path"])
        if ".." in path.parts: raise ValueError("Unsafe native instance path")
        relative=path.relative_to(root).as_posix()
        relative="" if relative=="." else relative
        if not npm_instance(relative): raise ValueError("Nonstandard physical npm instance")
        name=row.get("name",fallback)
        if relative in result:
            if (result[relative]["name"],result[relative]["version"])!=(name,row["version"]):
                raise ValueError("Contradictory physical npm instance")
            # npm ls expands repeated physical nodes at different logical paths.
            # A later occurrence may contain children absent from the first one.
            for key in ("resolved","integrity"):
                value=row.get(key)
                if value and result[relative][key] and value!=result[relative][key]:raise ValueError("Contradictory physical npm origin")
                if value:result[relative][key]=value
        else:result[relative]={"path":relative,"name":name,"version":row["version"],"resolved":row.get("resolved"),"integrity":row.get("integrity")}
        for dep,child in row.get("dependencies",{}).items(): visit(child,dep,depth+1)
    visit(raw,raw["name"])
    return result


def tar_metadata(path):
    with tarfile.open(path) as archive:
        # npm's extractor strips one root directory; older published archives
        # use roots such as jake-v10.9.4 rather than the modern package/ prefix.
        members=[m for m in archive.getmembers() if len(PurePosixPath(m.name).parts)==2 and
                 PurePosixPath(m.name).parts[-1]=="package.json" and ".." not in PurePosixPath(m.name).parts and not m.name.startswith("/")]
        if len(members)!=1 or not members[0].isfile() or members[0].size>2_000_000:
            raise ValueError("Invalid npm artifact metadata")
        return json.load(archive.extractfile(members[0]))


def make_npm_lock(spec,root):
    """Container-side production projection and native npm lock replay input."""
    root=Path(root);packages={};projection={}
    # Script/dev declarations are omitted by an explicit fixture profile, never
    # silently presented as the original project manifest or a deployed app.
    fields=("name","version","license","dependencies","optionalDependencies","peerDependencies","peerDependenciesMeta","engines","os","cpu")
    for key in fields:
        if key in spec["root_manifest"]: projection[key]=spec["root_manifest"][key]
    packages[""]=deepcopy(projection)
    for instance,row in spec["instances"].items():
        if not instance: continue
        artifact=contained(root,row["artifact_path"])
        raw=artifact.read_bytes();verify_integrity(raw,row["integrity"])
        meta=tar_metadata(artifact)
        if (meta.get("name"),meta.get("version"))!=(row["name"],row["version"]):
            raise ValueError("Artifact metadata contradicts frozen native snapshot")
        entry={k:meta[k] for k in fields if k in meta}
        entry.update(resolved=row["resolved"],integrity=row["integrity"])
        packages[instance]=entry
    target=root/"target";target.mkdir(exist_ok=False)
    save(target/"package.json",projection)
    save(target/"package-lock.json",{"name":projection["name"],"version":projection["version"],"lockfileVersion":3,"requires":True,"packages":packages})
    save(root/"production-projection.json",{"profile":"FROZEN_PRODUCTION_LOCK_REPLAY","removed_root_fields":sorted(set(spec["root_manifest"])-set(projection)),
         "original_manifest_sha256":fingerprint(spec["root_manifest"]),"projection_sha256":fingerprint(projection),
         "lifecycle_scripts":"disabled","source_application_build":"NOT_CLAIMED"})


def selected_python_metadata(relative):
    return bool(re.fullmatch(r"(?:lib|lib64)/python[0-9.]+/(?:site|dist)-packages/[^/]+\.dist-info/METADATA",relative))


def metadata_files(target,ecosystem):
    """Enumerate evidence before reading native identity labels; reject links."""
    target=Path(target).resolve();entries=[]
    pattern="*.dist-info/METADATA" if ecosystem=="pypi" else "package.json" if ecosystem=="npm" else "*.jar"
    for file in sorted(target.rglob(pattern)):
        relative=file.relative_to(target).as_posix();contained(target,relative)
        if not file.is_file(): raise ValueError("Metadata is not a regular file")
        if ecosystem=="pypi": selected=selected_python_metadata(relative);instance=relative.rsplit("/",1)[0]
        elif ecosystem=="npm":
            instance=relative[:-len("/package.json")] if relative!="package.json" else ""
            selected=npm_instance(instance)
        else: selected=True;instance=relative
        sha=digest(file)
        entries.append({"evidence_id":fingerprint([relative,sha]),"path":relative,"sha256":sha,"instance":instance,
                        "role":"SELECTED_METADATA" if selected else "NESTED_METADATA","format":ecosystem})
    if ecosystem=="npm" and (target/"package-lock.json").is_file():
        file=contained(target,"package-lock.json");sha=digest(file)
        entries.append({"evidence_id":fingerprint(["package-lock.json",sha]),"path":"package-lock.json","sha256":sha,
                        "instance":None,"role":"RESOLUTION_MANIFEST","format":"npm-lock"})
    return entries


def archive_properties(path):
    results=[]
    with zipfile.ZipFile(path) as archive:
        for item in archive.infolist():
            if not item.filename.endswith("/pom.properties") or item.file_size>65536: continue
            text=archive.read(item).decode("utf-8")
            props=dict(line.split("=",1) for line in text.splitlines() if "=" in line and not line.startswith(("#","!")))
            if all(props.get(k) for k in ("groupId","artifactId","version")):
                results.append({"name":props["groupId"]+":"+props["artifactId"],"version":props["version"],"member":item.filename})
    return results


def read_identity(target,entry):
    path=contained(Path(target),entry["path"])
    if digest(path)!=entry["sha256"]: raise ValueError("Target evidence digest changed")
    if entry["format"]=="pypi":
        if path.stat().st_size>2_000_000: raise ValueError("Oversized METADATA")
        data=email.message_from_bytes(path.read_bytes())
        if len(data.get_all("Name",[]))!=1 or len(data.get_all("Version",[]))!=1: raise ValueError("Ambiguous METADATA identity")
        name,version=canonicalize_name(data["Name"]),data["Version"]
    elif entry["format"]=="npm":
        if path.stat().st_size>2_000_000: raise ValueError("Oversized package.json")
        data=json.loads(path.read_text());name,version=data["name"],data["version"]
    else:
        candidates=archive_properties(path)
        values={(r["name"],r["version"]) for r in candidates}
        if len(values)!=1: raise ValueError("JAR identity unavailable or ambiguous")
        name,version=next(iter(values))
    return {"name":name,"version":version,"purl":coordinates(entry["format"],name,version)}


def capture_inventory(target,ecosystem,native_path,out):
    """Trusted inspection: emit public hash catalog and private native references."""
    target=Path(target).resolve();out=Path(out)
    entries=metadata_files(target,ecosystem)
    catalog={"schema_version":"materialized-evidence-v1","ecosystem":ecosystem,"entries":entries,
             "target_id":fingerprint(entries),"scope":"ALL_TOP_LEVEL_DISTRIBUTIONS" if ecosystem=="pypi" else
                "PRODUCTION_NODE_MODULE_INSTANCES" if ecosystem=="npm" else "EXTERNAL_RUNTIME_JAR_ARTIFACTS"}
    labels={};issues=[]
    if ecosystem=="pypi":
        native=json.loads(Path(native_path).read_text())
        for item in native["installed"]:
            location=PurePosixPath(item["metadata_location"])
            relative=location.relative_to(PurePosixPath("/out/target")).as_posix()+"/METADATA"
            if relative in labels: raise ValueError("Duplicate native metadata location")
            labels[relative]={"name":canonicalize_name(item["metadata"]["name"]),"version":item["metadata"]["version"]}
    elif ecosystem=="npm":
        native=json.loads(Path(native_path).read_text())
        for instance,row in npm_snapshot(native,issues).items():
            labels[(instance+"/" if instance else "")+"package.json"]={"name":row["name"],"version":row["version"]}
    else: native={"kind":"direct-jar-metadata"}
    reference=[]
    for entry in entries:
        if entry["role"]!="SELECTED_METADATA": continue
        try:
            actual=read_identity(target,entry)
            if ecosystem!="maven":
                expected=labels.get(entry["path"])
                if not expected: raise ValueError("No independently captured native label at this path")
                if (actual["name"],actual["version"])!=(expected["name"],expected["version"]):
                    raise ValueError("Native manager identity contradicts metadata bytes")
                label={**expected,"purl":coordinates(ecosystem,expected["name"],expected["version"])}
            else: label=actual
            reference.append({"evidence_id":entry["evidence_id"],"instance":entry["instance"],"path":entry["path"],
                              "sha256":entry["sha256"],**label})
        except (ValueError,KeyError) as exc: issues.append({"evidence_id":entry["evidence_id"],"status":"UNKNOWN","reason":str(exc)})
    save(out/"evidence/catalog.json",catalog)
    save(out/"oracle/reference.json",{"schema_version":"materialized-reference-v1","target_id":catalog["target_id"],"scope":catalog["scope"],
         "records":reference,"issues":issues,"native_source":"pip inspect" if ecosystem=="pypi" else "npm ls" if ecosystem=="npm" else "embedded pom.properties",
         "native_sha256":digest(native_path),
         "scope_completeness":"Metadata inventory only; not executable contents, imports or exploitability"})
    return {"entries":len(entries),"selected":sum(e["role"]=="SELECTED_METADATA" for e in entries),"verified_reference":len(reference),"issues":issues,"target_id":catalog["target_id"]}


def scanner_path(path):
    if not isinstance(path,str) or "\\" in path: raise ValueError("Unsupported scanner path")
    for prefix in ("/target/","/src/"):
        if path.startswith(prefix): path=path[len(prefix):];break
    path=path.lstrip("/")
    if ".." in PurePosixPath(path).parts: raise ValueError("Unsafe scanner evidence path")
    return path


def lock_corroboration(package,lock_entries,catalog,target,cache):
    """Coordinate-conditioned corroboration, never an identity accuracy label.

    Retain every physical candidate. Even a singleton is not promoted to a
    unique instance: the scanner cited a shared lockfile rather than that path.
    """
    refs=[r.get("referenceLocator") for r in package.get("externalRefs",[]) if r.get("referenceType")=="purl"]
    if len(refs)!=1:return []
    try:
        observed=PackageURL.from_string(refs[0])
        if observed.type!="npm" or not observed.version or observed.qualifiers or observed.subpath:return []
    except (ValueError,TypeError):return []
    index={e["path"]:e for e in catalog["entries"] if e["role"]=="SELECTED_METADATA"}
    candidates={}
    for entry in lock_entries:
        if entry["evidence_id"] in cache:
            candidates.update(cache[entry["evidence_id"]].get(observed.to_string(),{}));continue
        path=contained(Path(target),entry["path"])
        if digest(path)!=entry["sha256"]:raise ValueError("Target lock digest changed")
        if path.stat().st_size>10_000_000:raise ValueError("Oversized target lock")
        lock=json.loads(path.read_text())
        if lock.get("lockfileVersion") not in {2,3}:continue
        by_purl={}
        for instance,row in lock.get("packages",{}).items():
            if not npm_instance(instance):raise ValueError("Unsafe lock instance path")
            relative=(instance+"/" if instance else "")+"package.json"
            meta=index.get(relative)
            if not meta:continue
            actual=read_identity(target,meta)
            declared_name=row.get("name") or (instance.rsplit("node_modules/",1)[-1] if instance else lock.get("name"))
            if (actual["name"],actual["version"])!=(declared_name,row.get("version")):
                raise ValueError("Target lock contradicts installed metadata")
            by_purl.setdefault(actual["purl"],{})[meta["evidence_id"]]=meta
        cache[entry["evidence_id"]]=by_purl
        candidates.update(by_purl.get(observed.to_string(),{}))
    return sorted(candidates)


def match_files(document,catalog,target=None):
    """No identity/desired-version labels are accepted by this function."""
    if catalog.get("schema_version")!="materialized-evidence-v1": raise ValueError("Unsupported evidence catalog")
    if fingerprint(catalog["entries"])!=catalog["target_id"]: raise ValueError("Changed catalog")
    index={e["path"]:e for e in catalog["entries"]}
    if len(index)!=len(catalog["entries"]): raise ValueError("Duplicate catalog path")
    if any(e["evidence_id"]!=fingerprint([e["path"],e["sha256"]]) for e in catalog["entries"]):
        raise ValueError("Invalid catalog evidence identity")
    files={};duplicate=set()
    for item in document.get("files",[]):
        ref=item.get("SPDXID")
        if ref in files: duplicate.add(ref)
        files[ref]=item
    associations={};rows=[];lock_cache={}
    ref_counts=Counter(p.get("SPDXID") for p in document.get("packages",[]))
    for rel in document.get("relationships",[]):
        if rel.get("relationshipType")=="CONTAINS" or (rel.get("relationshipType")=="OTHER" and rel.get("comment","").startswith("evident-by:")):
            if rel.get("relatedSpdxElement") in files:
                associations.setdefault(rel.get("spdxElementId"),[]).append(rel["relatedSpdxElement"])
    for pkg in document.get("packages",[]):
        matches={};conflict=False;missing_digest=False
        for ref in associations.get(pkg.get("SPDXID"),[]):
            if ref in duplicate: conflict=True;continue
            item=files[ref]
            try: path=scanner_path(item.get("fileName",""))
            except ValueError: conflict=True;continue
            if path not in index: continue
            hashes={c.get("checksumValue","").lower() for c in item.get("checksums",[]) if c.get("algorithm","").replace("-","").upper()=="SHA256"}
            if not hashes:
                missing_digest=True;continue
            if len(hashes)!=1 or index[path]["sha256"] not in hashes:
                conflict=True;continue
            matches[index[path]["evidence_id"]]=index[path]
        selected=[e for e in matches.values() if e["role"]=="SELECTED_METADATA"]
        locks=[e for e in matches.values() if e["role"]=="RESOLUTION_MANIFEST"]
        corroborated=[]
        if not conflict and locks and target is not None:
            try:corroborated=lock_corroboration(pkg,locks,catalog,target,lock_cache)
            except (ValueError,KeyError,TypeError):conflict=True
        if not pkg.get("SPDXID") or ref_counts[pkg["SPDXID"]]!=1:status="UNKNOWN_AMBIGUOUS_PACKAGE_REF"
        elif conflict: status="UNKNOWN_CONTRADICTED_FILE_EVIDENCE"
        elif len(selected)==1: status="FILE_BOUND_INSTANCE"
        elif len(selected)>1: status="UNKNOWN_MULTIPLE_METADATA_INSTANCES"
        elif corroborated: status="LOCK_CORROBORATED_COORDINATE_GROUP"
        elif locks: status="UNKNOWN_LOCK_COORDINATES_UNSUPPORTED"
        elif matches: status="OBSERVED_NESTED_METADATA"
        elif missing_digest: status="UNKNOWN_STRONG_DIGEST_UNAVAILABLE"
        else: status="UNKNOWN_NO_FILE_BINDING"
        rows.append({"ref":pkg.get("SPDXID"),"status":status,"evidence_id":selected[0]["evidence_id"] if status=="FILE_BOUND_INSTANCE" else None,
                     "candidate_evidence_ids":sorted(matches),"coordinate_group_evidence_ids":corroborated,
                     "target_id":catalog["target_id"]})
    return {"target_id":catalog["target_id"],"records":rows,"counts":dict(Counter(r["status"] for r in rows)),
            "oracle_read":False,"interpretation":"File binding verifies metadata location and bytes; package identity is evaluated separately"}


def metadata_control(document,catalog,target,matches):
    if matches!=match_files(document,catalog,target):raise ValueError("Changed or unsupported binding proposals")
    result=deepcopy(document);proposals=[];errors=[]
    catalog_index={e["evidence_id"]:e for e in catalog["entries"]}
    by_ref={p["SPDXID"]:p for p in result.get("packages",[])}
    for row in matches["records"]:
        if row["status"]!="FILE_BOUND_INSTANCE": continue
        entry=catalog_index[row["evidence_id"]]
        try: metadata=read_identity(target,entry)
        except (ValueError,KeyError) as exc:
            errors.append({"ref":row["ref"],"status":"UNKNOWN","reason":str(exc)});continue
        package=by_ref[row["ref"]]
        before={"name":package.get("name"),"versionInfo":package.get("versionInfo"),
                "purls":[r.get("referenceLocator") for r in package.get("externalRefs",[]) if r.get("referenceType")=="purl"]}
        if not package.get("name"): package["name"]=metadata["name"]
        package["versionInfo"]=metadata["version"]
        package["externalRefs"]=[r for r in package.get("externalRefs",[]) if r.get("referenceType")!="purl"]+[
            {"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":metadata["purl"]}]
        after={"name":package.get("name"),"versionInfo":package.get("versionInfo"),"purls":[metadata["purl"]]}
        if before!=after:proposals.append({"ref":row["ref"],"evidence_id":entry["evidence_id"],"sha256":entry["sha256"],"before":before,"after":after})
    return result,{"proposals":proposals,"unresolved":errors,"oracle_read":False,"claims":"Target metadata declarations only; not executable/runtime safety"}


def identity_outcome(package,reference,ecosystem):
    refs=[r.get("referenceLocator") for r in package.get("externalRefs",[]) if r.get("referenceType")=="purl"]
    if len(set(refs))!=1:return None
    try:
        p=PackageURL.from_string(refs[0])
        if p.type=="pypi": p=p._replace(name=canonicalize_name(p.name))
        return p.to_string()==reference["purl"]
    except (ValueError,TypeError):return False


def evaluate_scope(document,recovered,matches,reference):
    if matches["target_id"]!=reference["target_id"]:raise ValueError("Prediction/reference target mismatch")
    labels={r["evidence_id"]:r for r in reference["records"]}
    before={p["SPDXID"]:p for p in document.get("packages",[])};after={p["SPDXID"]:p for p in recovered.get("packages",[])}
    rows=[]
    for row in matches["records"]:
        if row["status"]!="FILE_BOUND_INSTANCE":continue
        label=labels.get(row["evidence_id"])
        if not label:rows.append({"ref":row["ref"],"label_status":"UNKNOWN"});continue
        rows.append({"ref":row["ref"],"label_status":"EMBEDDED_METADATA_ONLY" if reference.get("native_source")=="embedded pom.properties" else "NATIVE_AND_METADATA_CROSSCHECKED","evidence_id":row["evidence_id"],
                     "identity_before":identity_outcome(before[row["ref"]],label,None),"identity_after":identity_outcome(after[row["ref"]],label,None),
                     "version_before":before[row["ref"]].get("versionInfo")==label["version"],"version_after":after[row["ref"]].get("versionInfo")==label["version"]})
    known=[r for r in rows if r["label_status"]=="NATIVE_AND_METADATA_CROSSCHECKED"]
    def fraction(key):
        values=[r[key] for r in known if r[key] is not None]
        return {"correct":sum(values),"eligible":len(values),"rate":sum(values)/len(values) if values else None}
    return {"records":rows,"file_bound_records":len(rows),"reference_eligible_records":len(known),
            "metadata_only_records":sum(r["label_status"]=="EMBEDDED_METADATA_ONLY" for r in rows),
            "identity_before":fraction("identity_before"),"identity_after":fraction("identity_after"),
            "version_before":fraction("version_before"),"version_after":fraction("version_after"),
            "coordinate_corroborated_records":sum(r["status"]=="LOCK_CORROBORATED_COORDINATE_GROUP" for r in matches["records"]),
            "coordinate_corroboration_accuracy":"UNMEASURED: coordinates participated in selection; not an independent correctness denominator",
            "unbound_records":len(matches["records"])-len(rows),"unbound_policy":"UNKNOWN, never a known false positive or safe",
            "scope":"Captured metadata inventory; not deployed installation or runtime exploitability"}

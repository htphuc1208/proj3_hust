"""Oracle-free coordinate and source-scope diagnostics; never promotion to G2.

A matching PURL identifies coordinates in the allowed candidate snapshot. It does
not prove an installed artifact, target membership, or dependency relationship.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import json
from pathlib import Path, PurePosixPath

from packageurl import PackageURL
from packaging.utils import canonicalize_name

from sbom_recovery.gold.gold_contracts import CaseManifest, contained
from sbom_recovery.gold.proof import identity
from sbom_recovery.evidence.storage import save


def canonical(value):
    parsed=PackageURL.from_string(value)
    if parsed.type=="pypi": parsed=parsed._replace(name=canonicalize_name(parsed.name))
    return parsed.to_string(),parsed


def family(parsed):
    # Coarse search key only: dropping qualifiers must never establish identity.
    return parsed.type,parsed.namespace,parsed.name


def path_role(path):
    parts=PurePosixPath(path.replace("\\","/").lstrip("/")).parts
    if ".." in parts: return "UNSAFE_OR_UNRESOLVED_PATH"
    if parts[:2]==(".github","workflows"): return "WORKFLOW_SOURCE"
    if any(p in {"example","examples","demo","demos"} for p in parts): return "EXAMPLE_SOURCE"
    if any(p in {"test","tests","testing"} for p in parts): return "TEST_SOURCE"
    if len(parts)==1 and parts[0] in {"pom.xml","package.json","pyproject.toml","setup.py","setup.cfg","uv.lock","package-lock.json"}:
        return "ROOT_DECLARATION_SOURCE"
    return "OTHER_SOURCE" if parts else "SOURCE_UNAVAILABLE"


def package_paths(document):
    files={f["SPDXID"]:f.get("fileName","") for f in document.get("files",[]) if f.get("SPDXID")}
    packages={p["SPDXID"]:p for p in document.get("packages",[]) if p.get("SPDXID")}
    result=defaultdict(set)
    for rel in document.get("relationships",[]):
        source,dest=rel.get("spdxElementId"),rel.get("relatedSpdxElement")
        if dest in files and (rel.get("relationshipType")=="CONTAINS" or (
                rel.get("relationshipType")=="OTHER" and rel.get("comment","").startswith("evident-by:"))):
            result[source].add(files[dest])
        # Trivy uses an application container whose name is the declaration path.
        if rel.get("relationshipType")=="CONTAINS" and source in packages:
            name=packages[source].get("name","")
            if name.endswith((".json",".toml",".xml",".lock",".txt",".yaml",".yml")):
                result[dest].add(name)
    for ref,pkg in packages.items():
        text=pkg.get("sourceInfo","")
        for prefix in ("package found in: ",):
            if text.startswith(prefix): result[ref].add(text[len(prefix):])
    return result


def audit_scopes(case_path,out):
    out=Path(out)
    if out.exists(): raise FileExistsError(out)
    case_path=Path(case_path).resolve();case=CaseManifest.model_validate_json(case_path.read_text())
    ids=[key for key in case.allowed_evidence if case.files[key].kind in {"scanner","resolver"}]
    case.verify_files(case_path.parent,ids)
    exact=defaultdict(list); families=defaultdict(list)
    for key in ids:
        if case.files[key].kind!="resolver": continue
        data=json.loads(contained(case_path.parent,case.files[key].path).read_text())
        if data.get("status")!="COMPLETE": continue
        if data.get("commit")!=case.commit or data.get("target")!=case.target or data.get("environment")!=case.environment:
            raise ValueError("Candidate report belongs to another context")
        for node in data["nodes"]:
            if not node.get("version") or node["version"] in {"unknown","unspecified"}: continue
            value=identity(case.ecosystem,node["name"],node["version"])
            normalized,parsed=canonical(value)
            exact[normalized].append(node["id"]);families[family(parsed)].append({"purl":normalized,"instance":node["id"]})
    records=[]
    for key in ids:
        item=case.files[key]
        if item.kind!="scanner": continue
        document=json.loads(contained(case_path.parent,item.path).read_text())
        if not str(document.get("spdxVersion","")).startswith("SPDX-2."):
            raise ValueError("Scope audit currently requires native SPDX 2.x scanner inputs")
        paths=package_paths(document)
        for pkg in document.get("packages",[]):
            ref=pkg.get("SPDXID","");raw={r["referenceLocator"] for r in pkg.get("externalRefs",[])
                if r.get("referenceType")=="purl" and r.get("referenceLocator")}
            row={"source_id":key,"source_sha256":item.sha256,"ref":ref,"name":pkg.get("name"),
                 "paths":sorted(paths[ref]),"path_roles":sorted({path_role(p) for p in paths[ref]}) or ["SOURCE_UNAVAILABLE"],
                 "candidate_instances":[],"scope_judgment":"CONTEXT_UNCERTAIN","promoted_to_resolved":False}
            if not raw: row["coordinate_status"]="NO_PURL"
            elif len(raw)>1: row["coordinate_status"]="CONFLICTING_PURLS"
            else:
                try:
                    value,parsed=canonical(next(iter(raw)));row["purl"]=value
                    if parsed.type!=case.ecosystem: row["coordinate_status"]="OTHER_ECOSYSTEM"
                    elif value in exact:
                        row["candidate_instances"]=exact[value]
                        row["coordinate_status"]="EXACT_COORDINATES_MULTIPLE_INSTANCES" if len(exact[value])>1 else "EXACT_COORDINATES_ONE_CANDIDATE"
                    elif family(parsed) in families:
                        row["coordinate_status"]="FAMILY_ONLY_DIFFERENT_COORDINATES"
                        row["family_candidates"]=families[family(parsed)]
                    else: row["coordinate_status"]="NOT_IN_PARTIAL_CANDIDATE_SNAPSHOT"
                except (ValueError,TypeError): row["coordinate_status"]="MALFORMED_PURL"
            records.append(row)
    result={"status":"SCOPE_DIAGNOSTIC_ONLY","case_id":case.case_id,"case_manifest_sha256":case.digest(),
        "candidate_snapshot":"PARTIAL; native production reports permitted by the case",
        "scanner_scope":"Source-tree inventory under the pilot capture protocol",
        "coordinate_counts":dict(Counter(r["coordinate_status"] for r in records)),
        "path_role_counts":dict(Counter(role for r in records for role in r["path_roles"])),
        "records":records,"promotion_count":0,"gold_labels_read":False,"correctness":"UNMEASURED",
        "limits":"Matching coordinates cannot establish runtime scope, installed artifact identity, or missing dependency edges. Unmatched candidates are not false positives."}
    out.mkdir(parents=True);save(out/"scope-audit.json",result);return result

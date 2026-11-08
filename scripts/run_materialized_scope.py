"""Materialize existing pilot targets and compare scanner scope using file hashes.

All target installation/build code runs in constrained containers. No LLM calls,
new repository selection, historical-install claim or deployed-app claim.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib
from urllib.parse import urlsplit
from urllib.parse import quote
from urllib.error import HTTPError
from urllib.request import Request,urlopen
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sbom_recovery.gold_contracts import CaseManifest,contained,fingerprint
from sbom_recovery.materialized_scope import digest,npm_snapshot,verify_integrity,evaluate_scope,metadata_files
from sbom_recovery.storage import save
from sbom_recovery.formats import validate_native
from scripts.collect_gold_pilot import unpack

ROOT=Path(__file__).resolve().parents[1]


def now():return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")


def fetch(url,host,limit=40_000_000):
    parsed=urlsplit(url)
    if parsed.scheme!="https" or parsed.hostname!=host or parsed.username or parsed.password:
        raise ValueError("Unexpected artifact origin")
    with urlopen(Request(url,headers={"User-Agent":"sbom-materialized-scope-v1"}),timeout=60) as response:
        if urlsplit(response.geturl()).hostname!=host:raise ValueError("Artifact redirected outside allowed origin")
        raw=response.read(limit+1)
    if len(raw)>limit:raise ValueError("Artifact size limit exceeded")
    return raw


def docker_run(image,command,mounts,log,*,network=False,timeout=600,tmp_bytes="1g",entrypoint=None,stdout_path=None,environment=None):
    name="sbom-scope-"+uuid.uuid4().hex
    args=["docker","run","--rm","--name",name,"--platform","linux/amd64","--read-only","--cap-drop=ALL",
          "--security-opt=no-new-privileges","--memory=3g","--cpus=2","--pids-limit=256","--user",f"{os.getuid()}:{os.getgid()}",
          "--tmpfs",f"/tmp:rw,exec,size={tmp_bytes}","-e","PYTHONDONTWRITEBYTECODE=1","-e","PYTHONPATH=/code"]
    if not network:args += ["--network","none"]
    for key,value in (environment or {}).items():args += ["-e",key+"="+value]
    for source,destination,mode in mounts:args += ["-v",str(Path(source).resolve())+":"+destination+":"+mode]
    if entrypoint:args += ["--entrypoint",entrypoint]
    args += [image,*command]
    started=now()
    try:
        with Path(log).open("w") as output:
            if stdout_path:
                with Path(stdout_path).open("w") as raw_output:
                    result=subprocess.run(args,stdout=raw_output,stderr=output,timeout=timeout)
            else:result=subprocess.run(args,stdout=output,stderr=subprocess.STDOUT,timeout=timeout)
        code=result.returncode
    except subprocess.TimeoutExpired:
        subprocess.run(["docker","stop","-t","2",name],capture_output=True)
        code=-1
    save(str(log)+".json",{"command":args,"started_at":started,"finished_at":now(),"returncode":code,
                           "network":"acquisition-enabled" if network else "none"})
    if code:raise RuntimeError("Container stage failed: "+str(log))
    return args


def prepare_python(case,case_root,out,image,reuse=None):
    wheels=out/"wheels";wheels.mkdir();dependency_hashes={}
    cached=Path(reuse)/"cases"/case.case_id if reuse else None
    if cached and (cached/"wheel-manifest.json").exists():
        expected=json.loads((cached/"wheel-manifest.json").read_text())
        for name,sha in expected.items():
            path=contained(cached,"wheels/"+name)
            if digest(path)!=sha:raise ValueError("Retained wheelhouse changed")
            shutil.copyfile(path,wheels/name)
        save(out/"wheel-replay.json",{"parent_store":str(cached),"hashes":expected,"root_rebuilt":False})
    else:
        source=out/"source";unpack(contained(case_root,case.files["source:archive"].path).read_bytes(),source)
        selected=source/case.target
        build=out/"build";build.mkdir()
        pyproject=selected/"pyproject.toml"
        requires=tomllib.loads(pyproject.read_text()).get("build-system",{}).get("requires",[]) if pyproject.exists() else []
        if not requires:requires=["setuptools>=40.8.0","wheel"]
        (build/"requires.txt").write_text("\n".join(requires)+"\n")
        command="python -m venv /tmp/build-env && /tmp/build-env/bin/pip install --report /out/tool-report.json -r /out/requires.txt > /out/tools.log 2>&1 && cp -R /src /tmp/project && /tmp/build-env/bin/pip wheel --no-deps --no-build-isolation --wheel-dir /out/root-wheels /tmp/project > /out/wheel.log 2>&1"
        docker_run(image,["sh","-c",command],[(selected,"/src","ro"),(build,"/out","rw")],out/"build.log",network=True)
        for path in sorted((build/"root-wheels").glob("*.whl")):
            contained(build,"root-wheels/"+path.name);shutil.copyfile(path,wheels/path.name)
        if not list((build/"root-wheels").glob("*.whl")):raise ValueError("No root wheel produced")
    for item in case.files.values():
        if item.kind=="artifact" and item.path.endswith(".whl"):
            original=contained(case_root,item.path);destination=wheels/original.name
            shutil.copyfile(original,destination);dependency_hashes[destination.name]=item.sha256
    for name,expected in dependency_hashes.items():
        if digest(wheels/name)!=expected:raise ValueError("Frozen dependency wheel changed")
    wheel_files=sorted(wheels.glob("*.whl"))
    for path in wheel_files:contained(out,"wheels/"+path.name)
    (out/"requirements.wheels").write_text("\n".join("/out/wheels/"+p.name+" --hash=sha256:"+digest(p) for p in wheel_files)+"\n")
    (out/"oracle").mkdir()
    command="python -m venv /out/target && /out/target/bin/python --version > /out/toolchain.txt && /out/target/bin/pip --version >> /out/toolchain.txt && /out/target/bin/pip install --no-index --no-deps --require-hashes --report /out/oracle/install-report.json -r /out/requirements.wheels > /out/oracle/install.log 2>&1 && /out/target/bin/pip check > /out/oracle/pip-check.log && /out/target/bin/pip inspect --local > /out/oracle/native.json"
    docker_run(image,["sh","-c",command],[(out,"/out","rw")],out/"install.log")
    save(out/"wheel-manifest.json",{p.name:digest(p) for p in wheel_files})
    return "NATIVE_OFFLINE_WHEEL_INSTALL"


def prepare_npm(case,case_root,out,image,worker,code,reuse=None):
    raw=json.loads(contained(case_root,case.files["native:raw"].path).read_text())
    placeholders=[];instances=npm_snapshot(raw,placeholders)
    artifact_dir=out/"artifacts";artifact_dir.mkdir();downloads={};upgrade_cache={}
    for path,row in instances.items():
        if not path:continue
        if not row["resolved"] or not row["integrity"]:raise ValueError("Incomplete pinned artifact origin")
        key=fingerprint([row["resolved"],row["integrity"]]);row["artifact_path"]="artifacts/"+key+".tgz"
        if not any(v.startswith(("sha256-","sha384-","sha512-")) for v in row["integrity"].split()):
            metadata_url="https://registry.npmjs.org/"+quote(row["name"],safe="")+"/"+quote(row["version"],safe="")
            metadata_raw=upgrade_cache.get(key)
            acquired_at=now();reused_from=None
            if metadata_raw is None:
                retained=Path(reuse)/"cases"/case.case_id/"integrity-upgrades" if reuse else None
                if retained and (retained/(key+".metadata.json")).is_file():
                    previous=json.loads((retained/(key+".json")).read_text());metadata_raw=(retained/(key+".metadata.json")).read_bytes()
                    if hashlib.sha256(metadata_raw).hexdigest()!=previous["metadata_sha256"]:raise ValueError("Retained registry metadata changed")
                    acquired_at=previous["acquired_at"];reused_from=str(retained/(key+".metadata.json"))
                else:metadata_raw=fetch(metadata_url,"registry.npmjs.org",5_000_000)
                upgrade_cache[key]=(metadata_raw,acquired_at,reused_from)
            else:metadata_raw,acquired_at,reused_from=metadata_raw
            metadata=json.loads(metadata_raw)
            if metadata.get("name")!=row["name"] or metadata.get("version")!=row["version"] or metadata["dist"]["tarball"]!=row["resolved"]:
                raise ValueError("Fresh registry metadata contradicts frozen artifact identity")
            row["legacy_integrity"]=row["integrity"];row["integrity"]=metadata["dist"].get("integrity","")
            upgrades=out/"integrity-upgrades";upgrades.mkdir(exist_ok=True)
            (upgrades/(key+".metadata.json")).write_bytes(metadata_raw)
            save(upgrades/(key+".json"),{"acquired_at":acquired_at,"reused_from":reused_from,"url":metadata_url,"metadata_file":key+".metadata.json","metadata_sha256":hashlib.sha256(metadata_raw).hexdigest(),
                "legacy_integrity":row["legacy_integrity"],"strong_integrity":row["integrity"],"registry_metadata":metadata})
        downloads[key]=row
    def download(item):
        key,row=item
        previous=Path(reuse)/"cases"/case.case_id/row["artifact_path"] if reuse else None
        raw=previous.read_bytes() if previous and previous.is_file() else fetch(row["resolved"],"registry.npmjs.org")
        verify_integrity(raw,row["integrity"])
        if row.get("legacy_integrity"):
            import base64
            expected=row["legacy_integrity"].split("-",1)
            if expected[0]!="sha1" or hashlib.sha1(raw).digest()!=base64.b64decode(expected[1],validate=True):
                raise ValueError("Strongly verified artifact differs from original legacy digest")
        return key,raw
    total=0
    with ThreadPoolExecutor(max_workers=4) as pool:
        for key,payload in pool.map(download,downloads.items()):
            total+=len(payload)
            if total>536870912:raise ValueError("Artifact store exceeds declared 512 MiB limit")
            (artifact_dir/(key+".tgz")).write_bytes(payload)
    manifest_file=next(v for v in case.files.values() if v.kind=="manifest" and v.path.endswith("/package.json"))
    root_manifest=json.loads(contained(case_root,manifest_file.path).read_text())
    save(out/"npm-spec.json",{"instances":instances,"root_manifest":root_manifest,"native_placeholders":placeholders})
    docker_run(worker,["-B","-m","sbom_recovery.materialized_worker","npm-lock","--spec","/out/npm-spec.json"],
               [(out,"/out","rw"),(code/"sbom_recovery","/code/sbom_recovery","ro")],out/"lock.log",entrypoint="python")
    (out/"oracle").mkdir()
    command='node --version > /out/toolchain.txt && npm --version >> /out/toolchain.txt || exit; find /out/artifacts -type f -name "*.tgz" -print0 | xargs -0 -n 32 npm cache add --offline --ignore-scripts --cache /out/npm-cache >> /out/cache.log 2>&1 || exit; cd /out/target && npm ci --offline --ignore-scripts --omit=dev --cache /out/npm-cache > /out/oracle/install.log 2>&1 && npm ls --all --omit=dev --long --json > /out/oracle/native.json'
    docker_run(image,["sh","-c",command],[(out,"/out","rw")],out/"install.log",timeout=900)
    save(out/"artifact-manifest.json",{p.name:digest(p) for p in artifact_dir.iterdir()})
    return "NATIVE_OFFLINE_PRODUCTION_LOCK_REPLAY"


def prepare_java(case,case_root,out):
    native=json.loads(contained(case_root,case.files["native:resolved"].path).read_text())
    target=out/"target";target.mkdir();sources=[]
    for node in native["nodes"]:
        if node["id"] in {"root","root project :"}:continue
        group,artifact=node["name"].split(":",1);version=node["version"]
        if not all(re.fullmatch(r"[A-Za-z0-9_.+-]+",part) for part in [group,artifact,version]):raise ValueError("Unsupported Maven coordinate")
        url="https://repo.maven.apache.org/maven2/"+group.replace(".","/")+"/"+artifact+"/"+version+"/"+artifact+"-"+version+".jar"
        raw=fetch(url,"repo.maven.apache.org")
        verified=None
        for algorithm in ("sha256","sha512","sha1"):
            try:expected=fetch(url+"."+algorithm,"repo.maven.apache.org",4096).decode().strip().split()[0].lower()
            except HTTPError as exc:
                if exc.code==404:continue
                raise
            if hashlib.new(algorithm,raw).hexdigest()!=expected:raise ValueError("Maven artifact checksum mismatch")
            verified={"algorithm":algorithm,"value":expected};break
        if verified is None:raise ValueError("No upstream checksum available")
        frozen_sha=hashlib.sha256(raw).hexdigest()
        path=target/(artifact+"-"+version+".jar");path.write_bytes(raw)
        sources.append({"url":url,"sha256":frozen_sha,"upstream_checksum":verified,"path":path.name,
                        "authenticity":"UNMEASURED; legacy SHA-1 is not collision-resistant authentication",
                        "coordinate_source":"permitted native report; not an identity gold label"})
    save(out/"artifact-manifest.json",sources)
    (out/"oracle").mkdir()
    save(out/"oracle/native.json",{"kind":"artifact-only","expected_artifacts":len(sources)})
    return "EXTERNAL_RUNTIME_JARS_ONLY_ROOT_APPLICATION_NOT_BUILT"


def acquire_java_db(destination,worker):
    """Acquire real tool data once; keep its bytes distinct from package gold."""
    destination=Path(destination).resolve();destination.mkdir(parents=True,exist_ok=False)
    cache=destination/"cache";cache.mkdir();(cache/"tmp").mkdir()
    try:
        docker_run(worker,["image","--download-java-db-only","--cache-dir","/cache","--no-progress"],
            [(ROOT/"research/.work/trivy","/scanner","ro"),(cache,"/cache","rw")],destination/"download.log",
            network=True,timeout=900,entrypoint="/scanner",environment={"TMPDIR":"/cache/tmp"})
        files={p.relative_to(cache).as_posix():digest(p) for p in cache.rglob("*") if p.is_file()}
        if not any(name.endswith("trivy-java.db") for name in files):raise ValueError("Java DB not acquired")
        record={"status":"ACQUIRED","acquired_at":now(),"files":files,
                "scanner_sha256":digest(ROOT/"research/.work/trivy"),"role":"SCANNER_TOOL_DATA_NOT_GOLD"}
    except Exception as exc:record={"status":"FAILED","error":str(exc),"acquired_at":now()}
    save(destination/"manifest.json",record);return record


def replay_target(case,out,reuse):
    """Copy a captured metadata target without rebuilding/resolving dependencies.

    This is a reanalysis of the retained development target, not a fresh install
    or executable-content attestation. Never silently fall back to the network.
    """
    retained=Path(reuse).resolve();parent= json.loads((retained/"manifest.json").read_text())
    original=next(r for r in parent["records"] if r["case_id"]==case.case_id)
    if original["status"]!="COMPLETE":raise ValueError("Retained target is not complete")
    if original["parent_case_sha256"]!=case.digest():raise ValueError("Retained target belongs to a different case")
    cached=retained/"cases"/case.case_id;catalog=json.loads((cached/"inspection/evidence/catalog.json").read_text())
    if metadata_files(cached/"target",case.ecosystem)!=catalog["entries"]:raise ValueError("Retained target metadata changed")
    if case.ecosystem!="maven" and json.loads((cached/"install.log.json").read_text())["returncode"]!=0:
        raise ValueError("Retained install failed")
    shutil.copytree(cached/"target",out/"target",symlinks=True)
    shutil.copytree(cached/"oracle",out/"oracle")
    if metadata_files(out/"target",case.ecosystem)!=catalog["entries"]:raise ValueError("Target copy changed metadata")
    if (cached/"toolchain.txt").exists():shutil.copyfile(cached/"toolchain.txt",out/"toolchain.txt")
    save(out/"replay-parent.json",{"run_manifest":str(retained/"manifest.json"),"run_manifest_sha256":digest(retained/"manifest.json"),
        "case_root":str(cached),"case_context_sha256":digest(cached/"source-context.json"),"metadata_target_id":catalog["target_id"],
        "catalog_sha256":digest(cached/"inspection/evidence/catalog.json"),"native_sha256":digest(cached/"oracle/native.json"),
        "original_profile":original["materialization_profile"],"profile":"CAPTURED_METADATA_TARGET_REANALYSIS",
        "fresh_installation":"NOT_CLAIMED","whole_executable_contents":"NOT_ATTESTED"})
    return "CAPTURED_METADATA_TARGET_REANALYSIS: "+original["materialization_profile"]


def run(parent_path,out,projects=None,reuse=None,java_db=None,reuse_targets=False,retry_failed=False):
    if reuse_targets and not reuse:raise ValueError("Target replay requires --reuse")
    if retry_failed and not reuse_targets:raise ValueError("Explicit failed-case retry requires --reuse-targets")
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=False)
    code=out/"source_bundle";code.mkdir()
    for name in ["sbom_recovery","scripts"]:shutil.copytree(ROOT/name,code/name,ignore=shutil.ignore_patterns("__pycache__"))
    worker=subprocess.check_output(["docker","image","inspect","sbom-recovery-worker:v1","--format","{{.Id}}"],text=True).strip()
    parent=json.loads(Path(parent_path).read_text());rows=[]
    previous={r["case_id"]:r for r in json.loads((Path(reuse)/"manifest.json").read_text())["records"]} if reuse_targets else {}
    db_cache=None
    if java_db:
        source=Path(java_db).resolve();record=json.loads((source/"manifest.json").read_text())
        if record["status"]!="ACQUIRED":raise ValueError("Java DB acquisition failed")
        for name,sha in record["files"].items():
            if digest(contained(source/"cache",name))!=sha:raise ValueError("Java DB changed")
        tool_data=out/"tool-data";tool_data.mkdir()
        db_cache=tool_data/"trivy-cache";shutil.copytree(source/"cache",db_cache)
        save(tool_data/"manifest.json",record)
    save(out/"protocol.json",{"parent_sha256":digest(Path(parent_path)),"worker_image":worker,
        "planned_scanners":["syft","trivy"],"llm_api_calls":0,"prediction_network":"none",
        "matching_policy":"PATH_AND_SHA256_ONLY; lock coordinates are corroboration, never a unique instance",
        "reference_policy":"Native installed metadata crosscheck; Java embedded metadata only",
        "source_bundle_hashes":{p.relative_to(code).as_posix():digest(p) for p in code.rglob("*.py")},
        "started_at":now(),"contemporary_materialization":True,"reuse_complete_targets":reuse_targets,"retry_failed_targets":retry_failed})
    for original in parent["records"]:
        if projects and original["case_id"] not in projects:continue
        root=out/"cases"/original["case_id"];root.mkdir(parents=True)
        row={"case_id":original["case_id"],"status":"RUNNING"};rows.append(row)
        try:
            case_path=Path(original["case_path"]);case=CaseManifest.model_validate_json(case_path.read_text());case.verify_files(case_path.parent)
            row.update(ecosystem=case.ecosystem,parent_case_sha256=case.digest(),source_commit=case.commit)
            save(root/"source-context.json",{"parent_case":str(case_path.resolve()),"parent_case_sha256":case.digest(),
                "source_commit":case.commit,"source_target":case.target,"parent_environment":case.environment,
                "materialization_started_at":now(),"historical_installation":"NOT_CLAIMED","release_artifact_mapping":"UNVERIFIED"})
            if reuse_targets and previous[case.case_id]["status"]=="COMPLETE":profile=replay_target(case,root,reuse)
            elif reuse_targets and not retry_failed:raise ValueError("Retained case failed; --retry-failed was not requested")
            elif case.ecosystem=="pypi":profile=prepare_python(case,case_path.parent,root,case.environment["image_id"],reuse)
            elif case.ecosystem=="npm":profile=prepare_npm(case,case_path.parent,root,case.environment["image_id"],worker,code,reuse)
            else:profile=prepare_java(case,case_path.parent,root)
            row["materialization_profile"]=profile
            inspection=root/"inspection";inspection.mkdir()
            docker_run(worker,["-B","-m","sbom_recovery.materialized_worker","inspect","--ecosystem",case.ecosystem,
                       "--native","/native/native.json","--out","/out"],[(root/"target","/target","ro"),(root/"oracle","/native","ro"),
                       (inspection,"/out","rw"),(code/"sbom_recovery","/code/sbom_recovery","ro")],root/"inspection.log",entrypoint="python")
            catalog_path=inspection/"evidence/catalog.json";catalog=json.loads(catalog_path.read_text())
            reference_path=inspection/"oracle/reference.json"
            inputs=root/"prediction-input";inputs.mkdir();shutil.copyfile(catalog_path,inputs/"catalog.json")
            scan_rows=[];scan_failures=[]
            for tool in ["syft","trivy"]:
                raw_scanner=inputs/(tool+".spdx.json")
                binary=ROOT/"research/.work"/tool
                scanner_command=["scan","dir:/target","-o","spdx-json"] if tool=="syft" else ["rootfs","--cache-dir","/cache",
                    "--offline-scan","--skip-db-update","--skip-java-db-update","--format","spdx-json","/target"]
                mounts=[(binary,"/scanner","ro"),(root/"target","/target","ro")]
                if tool=="trivy":
                    cache=root/"trivy-cache"
                    if db_cache and case.ecosystem=="maven" and catalog["entries"]:shutil.copytree(db_cache,cache)
                    else:cache.mkdir()
                    mounts.append((cache,"/cache","rw"))
                try:
                    docker_run(worker,scanner_command,mounts,root/(tool+"-scan.log"),entrypoint="/scanner",timeout=300,stdout_path=raw_scanner)
                    document=json.loads(raw_scanner.read_text());validity=validate_native(document)
                    if not validity["valid"]:raise ValueError("Scanner output failed native validation: "+str(validity["errors"]))
                    scan_rows.append({"id":tool,"filename":raw_scanner.name,"sha256":digest(raw_scanner),"binary_sha256":digest(binary),"native_validity":validity})
                except Exception as exc:
                    scan_failures.append({"scanner":tool,"status":"FAILED","error":str(exc),"log":str(root/(tool+"-scan.log"))})
            row["scanner_failures"]=scan_failures
            save(inputs/"config.json",{"catalog_sha256":digest(catalog_path),"scanners":scan_rows})
            predictions=root/"predictions";predictions.mkdir()
            command=docker_run(worker,["-B","-m","sbom_recovery.materialized_worker","predict","--input","/input","--out","/out"],
                [(inputs,"/input","ro"),(root/"target","/target","ro"),(predictions,"/out","rw"),(code/"sbom_recovery","/code/sbom_recovery","ro")],
                root/"prediction.log",entrypoint="python")
            seal={str(p.relative_to(predictions)):digest(p) for p in predictions.rglob("*.json")}
            save(root/"prediction-seal.json",seal)
            save(root/"worker-boundary.json",{"command":command,"oracle_mounted":False,"network":"none","target_id":catalog["target_id"],"input_config_sha256":digest(inputs/"config.json")})
            reference=json.loads(reference_path.read_text());scores=[]
            for scan in scan_rows:
                tool=scan["id"]
                original_doc=json.loads((inputs/(tool+".spdx.json")).read_text());bindings=json.loads((predictions/tool/"bindings.json").read_text())
                recovered=json.loads((predictions/tool/"recovered.spdx.json").read_text())
                control=json.loads((predictions/tool/"control.json").read_text())
                score=evaluate_scope(original_doc,recovered,bindings,reference);score.update(scanner=tool,binding_counts=bindings["counts"],
                    native_validity=validate_native(recovered),correction_records=len(control["proposals"]),control_unknowns=len(control["unresolved"]));scores.append(score)
            save(root/"evaluation.json",{"reference_sha256":digest(reference_path),"predictions_sealed_before_evaluation":True,"scores":scores,"scanner_failures":scan_failures})
            if json.loads(catalog_path.read_text())!=catalog:raise ValueError("Catalog changed during scanning")
            for entry in catalog["entries"]:
                if digest(contained(root/"target",entry["path"]))!=entry["sha256"]:raise ValueError("Target metadata changed during run")
            for name,expected in seal.items():
                if digest(predictions/name)!=expected:raise ValueError("Prediction changed after sealing")
            row.update(status="PARTIAL_SCANNERS" if scan_failures else "COMPLETE",target_id=catalog["target_id"],catalog_entries=len(catalog["entries"]),reference_records=len(reference["records"]),
                       reference_unknowns=len(reference["issues"]),case_root=str(root),scores=[{k:v for k,v in s.items() if k!="records"} for s in scores])
        except Exception as exc:row.update(status="FAILED",error=str(exc),case_root=str(root))
        save(out/"manifest.json",{"status":"RUNNING","records":rows});print(json.dumps(row),flush=True)
    result={"status":"COMPLETE_WITH_SCOPE_LIMITS" if all(r["status"]=="COMPLETE" for r in rows) else "PARTIAL_WITH_FAILURES", "records":rows,
            "llm_api_calls":0,"new_repositories_selected":0,"human_annotation":"PENDING","same_original_installation":"NOT_CLAIMED",
            "scope":"New materialized development targets from frozen versions; Java external JARs exclude unbuilt root applications"}
    save(out/"manifest.json",result);return result


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--parent",required=True);parser.add_argument("--out",required=True);parser.add_argument("--projects",nargs="+");parser.add_argument("--reuse");parser.add_argument("--java-db");parser.add_argument("--reuse-targets",action="store_true");parser.add_argument("--retry-failed",action="store_true")
    args=parser.parse_args();run(args.parent,args.out,args.projects,args.reuse,args.java_db,args.reuse_targets,args.retry_failed)

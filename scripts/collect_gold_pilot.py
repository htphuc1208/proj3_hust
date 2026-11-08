"""Freeze nine fresh source snapshots; execute native resolvers only inside containers.

No LLM calls, legacy SBOMs or previous gold labels participate in collection.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from urllib.request import Request, urlopen

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sbom_recovery.gold_contracts import CaseManifest, FrozenFile, contained
from sbom_recovery.gold_pipeline import build_gold
from sbom_recovery.storage import save

SPECS = [("pypi","psf/requests","."),("pypi","pallets/flask","."),("pypi","Textualize/rich","."),
         ("maven","google/gson","gson"),("maven","zxing/zxing","core"),("maven","ReactiveX/RxJava","."),
         ("npm","mde/ejs","."),("npm","jzaefferer/jquery-validation","."),("npm","developit/microbundle",".")]
IMAGES = {"pypi":"python:3.11-slim","maven":"maven:3.9.9-eclipse-temurin-17","npm":"node:22-bookworm-slim"}


def now(): return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fetch(url, limit=500_000_000):
    with urlopen(Request(url,headers={"User-Agent":"evidence-gold-pilot-v2"}),timeout=60) as response:
        raw = response.read(limit+1)
    if len(raw)>limit: raise ValueError("Acquisition byte limit exceeded")
    return raw


def unpack(raw, destination):
    destination.mkdir(parents=True,exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        total = 0
        for item in archive:
            rel = Path(*Path(item.name).parts[1:])
            if not rel.parts: continue
            if item.issym() or item.islnk(): continue
            if not (item.isfile() or item.isdir()): raise ValueError("Special archive entry")
            target = contained(destination,rel.as_posix())
            if item.isdir(): target.mkdir(parents=True,exist_ok=True); continue
            total += item.size
            if total > 1_500_000_000: raise ValueError("Source expansion limit exceeded")
            target.parent.mkdir(parents=True,exist_ok=True)
            with archive.extractfile(item) as src, target.open("wb") as dst:
                shutil.copyfileobj(src,dst)
            target.chmod(0o755 if item.mode & 0o111 else 0o644)


GRADLE_INIT = '''import groovy.json.JsonOutput
gradle.projectsEvaluated {
  rootProject.tasks.register('evidenceGoldGraph') {
    doLast {
      def conf = rootProject.configurations.findByName('runtimeClasspath')
      if (conf == null) throw new GradleException('runtimeClasspath unavailable')
      def result = conf.incoming.resolutionResult
      def nodes = result.allComponents.collect { c ->
        def m = c.moduleVersion
        [id: c.id.displayName, name: m.group + ':' + m.name, version: m.version]
      }
      def edges = []
      result.allComponents.each { c -> c.dependencies.each { d ->
        if (!(d instanceof org.gradle.api.artifacts.result.ResolvedDependencyResult)) throw new GradleException('Unresolved dependency')
        edges.add([c.id.displayName, d.selected.id.displayName])
      }}
      new File('/out/native.json').text = JsonOutput.toJson([nodes:nodes,edges:edges,source_model:[name:rootProject.group + ':' + rootProject.name,version:rootProject.version.toString()]])
    }
  }
}
'''


from sbom_recovery.native_graph import normalize


def collect(out, cutoff, limit=None, snapshots=None, projects=None):
    out=Path(out).resolve(); out.mkdir(parents=True,exist_ok=False)
    records=[]
    save(out/"selection.json",{"schema_version":"pilot-selection-v2","selected_before_method_scores":True,
        "source_cutoff":cutoff,"partition":"development","specs":SPECS,"replacement_policy":"No score-based replacement; retain failures",
        "source_sha256":sha(__file__),"legacy_inputs_reused":False})
    for ecosystem,repository,target in SPECS[:limit]:
        if projects and repository.split("/")[-1] not in projects: continue
        name=repository.split("/")[-1]; case_id="fresh-"+ecosystem+"-"+name
        root=out/"cases"/case_id; root.mkdir(parents=True)
        row={"case_id":case_id,"repository":repository,"status":"COLLECTING"}; records.append(row)
        try:
            previous=Path(snapshots)/"cases"/case_id if snapshots else None
            if previous and (previous/"case.json").exists():
                prior=CaseManifest.model_validate_json((previous/"case.json").read_text()); prior.verify_files(previous)
                commit=prior.commit
                response=(previous/"commit-response.json").read_bytes()
                raw=(previous/"source.tar.gz").read_bytes()
                save(root/"snapshot-reuse.json",{"parent_case_sha256":sha(previous/"case.json"),"selection":"same commit; build-only correction"})
            else:
                response=fetch(f"https://api.github.com/repos/{repository}/commits?until={cutoff}&per_page=1")
                commit=json.loads(response)[0]["sha"]
                raw=fetch(f"https://codeload.github.com/{repository}/tar.gz/{commit}")
            save(root/"commit-response.json",json.loads(response))
            (root/"source.tar.gz").write_bytes(raw); unpack(raw,root/"source")
            source=root/"source"/target; native=root/"native"; native.mkdir()
            image=IMAGES[ecosystem]
            if repository=="ReactiveX/RxJava":
                dockerfile=out/"gradle-toolchain"; dockerfile.mkdir(exist_ok=True)
                (dockerfile/"Dockerfile").write_text("FROM maven:3.8.6-eclipse-temurin-8 AS jdk8\nFROM maven:3.9.9-eclipse-temurin-17\nCOPY --from=jdk8 /opt/java/openjdk /opt/jdk8\n")
                with (dockerfile/"build.log").open("w") as log:
                    subprocess.run(["docker","build","-t","sbom-gold-gradle:17-8",str(dockerfile)],stdout=log,stderr=subprocess.STDOUT,check=True,timeout=300)
                image="sbom-gold-gradle:17-8"
            check=subprocess.run(["docker","image","inspect",image,"--format","{{.Id}}"],capture_output=True,text=True)
            if check.returncode:
                subprocess.run(["docker","pull",image],check=True,stdout=(native/"pull.log").open("w"),stderr=subprocess.STDOUT,timeout=300)
                image_id=subprocess.check_output(["docker","image","inspect",image,"--format","{{.Id}}"],text=True).strip()
            else: image_id=check.stdout.strip()
            env={"os":"linux","arch":"x86_64","runtime":image,"image_id":image_id,"extras":[]}
            if ecosystem=="pypi":
                command="python -m venv /tmp/env && /tmp/env/bin/pip install --report /out/install-report.json . > /out/install.log 2>&1 && /tmp/env/bin/pip check > /out/check.log && /tmp/env/bin/pip inspect --local > /out/native.json"
            elif ecosystem=="npm":
                command="if [ -f package-lock.json ]; then npm ci --omit=dev --ignore-scripts > /out/install.log 2>&1; else npm install --omit=dev --ignore-scripts > /out/install.log 2>&1; fi && npm ls --all --omit=dev --long --json > /out/native.json"
            elif (source/"pom.xml").exists():
                command="mvn -B -DskipTests -Dmaven.repo.local=/out/m2 org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree -Dscope=runtime -DoutputType=json -DoutputFile=/out/native.json > /out/install.log 2>&1"
            else:
                (native/"gold.init.gradle").write_text(GRADLE_INIT)
                command="./gradlew --no-daemon -Porg.gradle.java.installations.paths=/opt/jdk8 -I /out/gold.init.gradle evidenceGoldGraph > /out/install.log 2>&1"
            # Only temporary copies execute. No host credentials, daemon socket, oracle or writable source mount.
            prefix="cp -R /src /tmp/project && cd /tmp/project/"+target+" && "
            container="gold-pilot-"+name.lower()
            args=["docker","run","--rm","--name",container,"--platform","linux/amd64","--cap-drop=ALL",
                "--security-opt=no-new-privileges","--read-only","--memory=2g","--cpus=2","--pids-limit=256",
                "--user",f"{os.getuid()}:{os.getgid()}","--env","MAVEN_OPTS=-Duser.home=/tmp",
                "--env","GRADLE_USER_HOME=/tmp/gradle","--env","npm_config_cache=/tmp/npm-cache",
                "--tmpfs","/tmp:rw,exec,size=1g","--tmpfs","/root:rw,exec,size=512m",
                "-v",str(root/"source")+":/src:ro","-v",str(native)+":/out:rw",image_id,"sh","-c",prefix+command]
            save(native/"execution.json",{"command":args,"started_at":now(),"network":"acquisition enabled; frozen outputs retained",
                 "scope":"source snapshot installed/resolved now; not historical environment truth"})
            try:
                run=subprocess.run(args,capture_output=True,text=True,timeout=600)
                (native/"container.log").write_text(run.stdout+run.stderr)
                status="COMPLETE" if run.returncode==0 else "FAILED"
                row["resolver_exit_code"]=run.returncode
            except subprocess.TimeoutExpired:
                subprocess.run(["docker","stop","-t","2",container],capture_output=True)
                status="FAILED"; row["resolver_failure"]="TIMEOUT"
            files={"source:archive":FrozenFile(path="source.tar.gz",sha256=sha(root/"source.tar.gz"),kind="source"),
                   "source:commit":FrozenFile(path="commit-response.json",sha256=sha(root/"commit-response.json"),kind="source")}
            for candidate in sorted(source.iterdir()):
                if candidate.name in {"pyproject.toml","setup.cfg","setup.py","package.json","pom.xml","build.gradle","build.gradle.kts"} and candidate.is_file():
                    files["manifest:"+candidate.name]=FrozenFile(path=candidate.relative_to(root).as_posix(),sha256=sha(candidate),kind="manifest")
            report={"status":status,"commit":commit,"target":target,"environment":env,"nodes":[],"edges":[]}
            if status=="COMPLETE":
                try: report["nodes"],report["edges"]=normalize(ecosystem,json.loads((native/"native.json").read_text()),name)
                except (ValueError,KeyError) as exc: report["status"]="FAILED"; row["normalization_error"]=str(exc)
            save(native/"resolved.json",report)
            if (native/"native.json").exists():
                files["native:raw"]=FrozenFile(path="native/native.json",sha256=sha(native/"native.json"),kind="resolver")
                report["raw_evidence_id"]="native:raw"
                report["root_name"]=name
                save(native/"resolved.json",report)
            files["native:resolved"]=FrozenFile(path="native/resolved.json",sha256=sha(native/"resolved.json"),kind="resolver")
            case=CaseManifest(case_id=case_id,repository="https://github.com/"+repository,commit=commit,ecosystem=ecosystem,
                target=target,environment=env,evidence_cutoff=now(),files=files,allowed_evidence=list(files),
                resolution_status=report["status"],resolution_notes="Contemporary resolution of frozen source; no release/artifact equivalence claimed")
            save(root/"case.json",case.model_dump(mode="json"))
            row.update(status="CAPTURED",resolution_status=report["status"],commit=commit,
                       gold=build_gold(root/"case.json",out/"gold"/case_id))
        except Exception as exc:
            row.update(status="FAILED",error=str(exc))
        save(out/"collection.json",{"status":"IN_PROGRESS","records":records})
        print(json.dumps(row),flush=True)
    result={"status":"CAPTURED_WITH_EXPLICIT_FAILURES" if any(r["status"]!="CAPTURED" or r.get("resolution_status")!="COMPLETE" for r in records) else "CAPTURED",
            "records":records,"human_review":"PENDING","llm_api_calls":0,"scientific_superiority":"UNMEASURED"}
    save(out/"collection.json",result)
    return result


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--out",required=True)
    parser.add_argument("--source-cutoff",default="2025-12-31T23:59:59Z")
    parser.add_argument("--limit",type=int)
    parser.add_argument("--snapshots")
    parser.add_argument("--projects",nargs="+")
    args=parser.parse_args()
    collect(args.out,args.source_cutoff,args.limit,args.snapshots,args.projects)

"""Provenance, isolation and conservative assessment for the Level 2/3 pilot."""
from __future__ import annotations

import ast
from collections import Counter, deque
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
from urllib.request import urlopen
import uuid
import zipfile

from sbom_recovery.evidence.storage import save
from .reachability_worker import PAYLOAD


def _find_repo_root() -> Path:
    p = Path(__file__).resolve()
    for parent in p.parents:
        if (parent / '.git').exists() or (parent / 'pyproject.toml').exists():
            return parent
    return p.parents[2]

ROOT = _find_repo_root()
PROFILE_SOURCES = {
    "direct": 'import yaml\n\ndef entry(text):\n    return yaml.load(text, Loader=yaml.FullLoader)\n',
    "wrapper": ('from yaml import load as parse\nfrom yaml import FullLoader\n\n'
                'def decode(text):\n    return parse(text, Loader=FullLoader)\n\n'
                'def entry(text):\n    return decode(text)\n'),
    "safe": 'import yaml\n\ndef entry(text):\n    return yaml.load(text, Loader=yaml.SafeLoader)\n',
    "cooccurrence": 'import yaml\n\ndef entry(text):\n    return {"ignored": True}\n',
    "guard": ('import yaml\n\ndef entry(text):\n    if "!!python/" in text:\n'
              '        raise ValueError("tag rejected by application guard")\n'
              '    return yaml.load(text, Loader=yaml.FullLoader)\n'),
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def timestamp():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def read(path):
    return json.loads(Path(path).read_text())


def acquire(url, path, expected=None):
    with urlopen(url, timeout=60) as response:
        raw = response.read()
    sha = hashlib.sha256(raw).hexdigest()
    if expected is not None and sha != expected:
        raise ValueError("Artifact digest mismatch: " + url)
    Path(path).write_bytes(raw)
    return {"url": url, "sha256": sha, "bytes": len(raw), "acquired_at": timestamp()}


def source_member(name):
    path = PurePosixPath(name)
    if (path.is_absolute() or ".." in path.parts or "\\" in name
            or path.as_posix() != name):
        raise ValueError("Non-normalized archive member")
    return path


def extract_yaml(archive, destination):
    """Copy regular Python source members only; never execute packaging code."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    count = 0
    with tarfile.open(archive, "r:gz") as stream:
        for item in stream.getmembers():
            path = source_member(item.name)
            if len(path.parts) != 4 or path.parts[1:3] != ("lib3", "yaml") or path.suffix != ".py":
                continue
            if not item.isfile() or item.size > 2_000_000:
                raise ValueError("Invalid library source member")
            target = destination / path.name
            if target.exists():
                raise ValueError("Duplicate library source member")
            target.write_bytes(stream.extractfile(item).read())
            count += 1
    if count < 10 or not (destination / "__init__.py").is_file():
        raise ValueError("Incomplete release source")


def extract_analyzer(archive, destination, commit):
    destination = Path(destination)
    with tarfile.open(archive, "r:gz") as stream:
        for item in stream.getmembers():
            path = source_member(item.name)
            if path.parts[0] != "PyCG-" + commit:
                raise ValueError("Unexpected analyzer archive root")
            relative = PurePosixPath(*path.parts[1:])
            if not relative.parts or relative.parts[0] != "pycg" or relative.suffix != ".py":
                continue
            if not item.isfile() or item.size > 2_000_000:
                raise ValueError("Invalid analyzer source member")
            target = destination / relative
            if target.exists():
                raise ValueError("Duplicate analyzer member")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(stream.extractfile(item).read())
    if not (destination / "pycg/__main__.py").is_file():
        raise ValueError("Pinned source has no pycg CLI")


def prepare(out, config):
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    config = read(config)
    acquisition, build = out / "acquisition", out / "build"
    acquisition.mkdir(); build.mkdir()
    receipts = {}
    for version, spec in config["versions"].items():
        metadata = acquisition / ("PyYAML-" + version + ".json")
        receipts[metadata.name] = acquire("https://pypi.org/pypi/PyYAML/" + version + "/json", metadata)
        sources = [row for row in read(metadata)["urls"]
                   if row["packagetype"] == "sdist" and row["digests"]["sha256"] == spec["sha256"]]
        if len(sources) != 1:
            raise ValueError("Cannot uniquely identify pinned sdist")
        archive = acquisition / ("PyYAML-" + version + ".tar.gz")
        receipts[archive.name] = acquire(sources[0]["url"], archive, spec["sha256"])
        pristine = out / "pristine" / version / "yaml"
        extract_yaml(archive, pristine)
        for profile in config["profiles"]:
            root = build / "analysis" / version / profile
            shutil.copytree(pristine, root / "yaml")
            (root / "app.py").write_text(PROFILE_SOURCES[profile])
    analyzer = config["analyzer"]
    metadata = acquisition / "pycg-commit.json"
    receipts[metadata.name] = acquire("https://api.github.com/repos/vitsalis/PyCG/commits/" + analyzer["commit"], metadata)
    if read(metadata)["sha"] != analyzer["commit"]:
        raise ValueError("Analyzer commit mismatch")
    archive = acquisition / "pycg-source.tar.gz"
    receipts[archive.name] = acquire(analyzer["source_archive"], archive, analyzer["source_archive_sha256"])
    extract_analyzer(archive, build / "tools", analyzer["commit"])
    # Download setuptools wheel for pkg_resources in isolated environment with -S flag
    setuptools_version = "75.6.0"
    setuptools_url = f"https://files.pythonhosted.org/packages/py3/s/setuptools/setuptools-{setuptools_version}-py3-none-any.whl"
    setuptools_sha = "ce74b49e8f7110f9bf04883b730f4765b774ef3ef28f722cce7c273d253aaf7d"
    setuptools_wheel = acquisition / f"setuptools-{setuptools_version}-py3-none-any.whl"
    receipts[setuptools_wheel.name] = acquire(setuptools_url, setuptools_wheel, setuptools_sha)
    # Extract wheel to /tools alongside PyCG
    import zipfile
    with zipfile.ZipFile(setuptools_wheel) as wheel:
        for name in wheel.namelist():
            if name.startswith("setuptools/") or name.startswith("pkg_resources/"):
                target = build / "tools" / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(wheel.read(name))
    shutil.copyfile(ROOT / "sbom_recovery/reachability_worker.py", build / "worker.py")
    # Base image python:3.11-slim includes setuptools with pkg_resources
    (build / "Dockerfile").write_text(
        "FROM " + config["base_image_reference"] + "\n"
        "COPY analysis /analysis\nCOPY tools /tools\n"
        "COPY worker.py /pilot/worker.py\nUSER 65534:65534\n"
        'ENTRYPOINT ["python", "-B", "-S", "/pilot/worker.py"]\n')
    files = {str(p.relative_to(build)): digest(p) for p in sorted(build.rglob("*")) if p.is_file()}
    plan = {"schema_version": "reachability-plan-v1", "created_at": timestamp(), "config": config,
            "receipts": receipts, "build_files": files,
            "execution_order": "probe, all static outputs, static seal, audit controls, runtime matrix",
            "runtime_observations_available_to_static": False, "llm_calls": 0}
    save(out / "plan.json", plan)
    shutil.copyfile(__file__, out / "executed-controller.py")
    return plan


def shortest_path(graph, start, target):
    if not isinstance(graph, dict) or start not in graph:
        return None
    queue = deque([(start, [start])]); visited = {start}
    while queue:
        node, route = queue.popleft()
        if node == target:
            return route
        for successor in sorted(graph.get(node, [])):
            if successor not in visited:
                visited.add(successor); queue.append((successor, route + [successor]))
    return None


def symbol_locations(root):
    locations = {}
    root = Path(root)
    for file in sorted(root.rglob("*.py")):
        module = ".".join(file.relative_to(root).with_suffix("").parts)
        if module.endswith(".__init__"):
            module = module[:-len(".__init__")]
        def visit(tree, prefix):
            for child in ast.iter_child_nodes(tree):
                if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    symbol = prefix + "." + child.name
                    locations[symbol] = {"file": str(file.relative_to(root)), "line": child.lineno,
                                         "sha256": digest(file)}
                    visit(child, symbol)
        visit(ast.parse(file.read_text()), module)
    return locations


def static_assessment(raw, config, root):
    graph = raw.get("graph") if raw.get("status") == "COMPLETE" else None
    locations = symbol_locations(root)
    result = {"status": raw["status"], "entry_symbol": config["entry_symbol"],
              "entry_in_graph": bool(graph and config["entry_symbol"] in graph),
              "provenance": "Raw PyCG adjacency only; source locations added after prediction"}
    for field, target in [("api_path", config["api_symbol"]), ("constructor_path", config["patch_linked_symbol"])]:
        route = shortest_path(graph, config["entry_symbol"], target)
        result[field] = {"status": "OBSERVED" if route else "UNKNOWN", "target": target,
                         "symbols": route, "locations": [locations.get(s) for s in route] if route else []}
    return result


def matching_audit(raw, *, require_library_stack):
    events = raw.get("audit_events", [])
    if not isinstance(raw.get("expected_code_signature"), dict) or not raw["expected_code_signature"]:
        return False
    expression_hash = hashlib.sha256(b"40 + 2").hexdigest()
    for i, compile_event in enumerate(events):
        if compile_event.get("event") != "compile" or compile_event.get("source_sha256") != expression_hash:
            continue
        for event in events[i + 1:]:
            if event.get("event") != "exec":
                continue
            # Check exact signature match or explicit matches_expected flag
            signature_match = (event.get("signature") == raw.get("expected_code_signature")
                               or event.get("matches_expected") is True)
            if not signature_match:
                continue
            if not require_library_stack or all(
                any(frame.get("file") == "yaml/constructor.py" for frame in e.get("stack", []))
                for e in [compile_event, event]
            ):
                return True
    return False


def runtime_assessment(raw, *, instrumentation_valid):
    calls = raw.get("python_calls", [])
    error = raw.get("error")
    expected_rejection = bool(error and (
        (error.get("type") == "ConstructorError" and error.get("module") == "yaml.constructor")
        or (error.get("type") == "ValueError" and error.get("message") == "tag rejected by application guard")))
    if raw.get("status") != "COMPLETE" or not instrumentation_valid or (error and not expected_rejection):
        status = "UNKNOWN"
    elif (raw.get("input_kind") == "arithmetic" and raw.get("input_sha256") == hashlib.sha256(PAYLOAD.encode()).hexdigest()
          and raw.get("is_arithmetic_tuple") and not error and matching_audit(raw, require_library_stack=True)):
        status = "BENIGN_FAULT_WITNESSED"
    else:
        status = "NOT_OBSERVED_FOR_THIS_INPUT"
    return {"fault_witness": status, "dynamic_function_entry": {
                "status": "OBSERVED" if any(r.get("file") == "yaml/constructor.py" and
                    r.get("function") == "FullConstructor.construct_python_object_new" for r in calls) else "NOT_OBSERVED",
                "scope": "THIS_INPUT_EXECUTION"},
            "instrumentation_valid": instrumentation_valid,
            "product_vex": "under_investigation", "confidence": "UNMEASURED"}


def verify_build(out):
    out = Path(out)
    plan = read(out / "plan.json")
    actual = {str(p.relative_to(out / "build")): digest(p)
              for p in (out / "build").rglob("*") if p.is_file()}
    if actual != plan["build_files"]:
        raise ValueError("Build context changed after plan freeze")
    for name, receipt in plan["receipts"].items():
        if digest(out / "acquisition" / name) != receipt["sha256"]:
            raise ValueError("Acquisition bytes changed")
    return plan


def container_case(image, arguments, out):
    """Fresh process, zero bind mounts; inspect actual boundary before start."""
    out = Path(out); out.mkdir(parents=True, exist_ok=False)
    name = "sbom-reachability-" + uuid.uuid4().hex
    command = ["docker", "create", "--name", name, "--network=none", "--read-only",
               "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=65534:65534",
               "--tmpfs=/tmp:rw,mode=1777", "-e", "PYTHONDONTWRITEBYTECODE=1", image, *arguments]
    subprocess.run(command, check=True, capture_output=True, text=True)
    try:
        info = json.loads(subprocess.check_output(["docker", "inspect", name], text=True))[0]
        host = info["HostConfig"]
        env = [v.split("=", 1)[0] for v in info["Config"]["Env"]]
        if (host["NetworkMode"] != "none" or not host["ReadonlyRootfs"] or info["Mounts"]
                or host.get("Binds") or info["Config"]["User"] != "65534:65534"
                or host["CapDrop"] != ["ALL"] or "no-new-privileges" not in host["SecurityOpt"]
                or set(env) - {"PATH", "LANG", "GPG_KEY", "PYTHON_VERSION", "PYTHON_SHA256", "PYTHONDONTWRITEBYTECODE"}):
            save(out / "boundary-failure.json", {"network": host["NetworkMode"],
                 "read_only_root": host["ReadonlyRootfs"], "mounts": info["Mounts"],
                 "environment_variable_names": env, "security_options": host["SecurityOpt"]})
            raise ValueError("Runtime boundary failed")
        save(out / "boundary.json", {"command": command, "image": info["Image"],
             "network": host["NetworkMode"], "read_only_root": host["ReadonlyRootfs"],
             "mounts": info["Mounts"], "cap_drop": host["CapDrop"], "security_options": host["SecurityOpt"],
             "user": info["Config"]["User"], "environment_variable_names": env,
             "checked_at": timestamp(), "host_tree_mounted": False, "credentials_mounted": False})
        start = timestamp()
        completed = subprocess.run(["docker", "start", "-a", name], capture_output=True, text=True)
        (out / "stdout.log").write_text(completed.stdout)
        (out / "stderr.log").write_text(completed.stderr)
        state = json.loads(subprocess.check_output(["docker", "inspect", name], text=True))[0]["State"]
        save(out / "process.json", {"started_at": start, "finished_at": timestamp(),
             "command_returncode": completed.returncode, "container_state": state})
        if state["ExitCode"] != 0 or completed.returncode != 0:
            result = {"status": "CONTAINER_ERROR", "exit_code": state["ExitCode"]}
        else:
            try:
                result = json.loads(completed.stdout)
            except ValueError:
                result = {"status": "INVALID_WORKER_OUTPUT"}
        save(out / "result.json", result)
        return result
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True)


def run(out):
    out = Path(out).resolve()
    plan = verify_build(out); config = plan["config"]
    if (out / "image.json").exists():
        raise ValueError("Execution already started; retain this run and use a new output directory")
    base = json.loads(subprocess.check_output(["docker", "image", "inspect", config["base_image_reference"]], text=True))[0]
    if base["Id"] != config["base_image"]:
        raise ValueError("Base image tag no longer matches the frozen image ID")
    save(out / "base-image.json", {"reference": config["base_image_reference"], "image": base["Id"],
                                  "layers": base["RootFS"]["Layers"], "checked_at": timestamp()})
    image_id_file = out / "image.id"
    build = subprocess.run(["docker", "build", "--network=none", "--iidfile", str(image_id_file), str(out / "build")],
                           capture_output=True, text=True)
    (out / "build.log").write_text(build.stdout + build.stderr)
    build.check_returncode()
    image = image_id_file.read_text().strip()
    built = json.loads(subprocess.check_output(["docker", "image", "inspect", image], text=True))[0]
    if built["RootFS"]["Layers"][:len(base["RootFS"]["Layers"])] != base["RootFS"]["Layers"]:
        raise ValueError("Built image is not derived from the frozen base layers")
    save(out / "image.json", {"image": image, "base_image": config["base_image"],
                               "plan_sha256": digest(out / "plan.json"), "created_at": timestamp()})
    probe = container_case(image, ["probe"], out / "probe")
    if probe.get("environment", {}).get("python") != config["expected_python"]:
        raise ValueError("Unexpected interpreter")
    statics = {}
    for version in config["versions"]:
        for profile in config["profiles"]:
            key = version + "/" + profile
            raw = container_case(image, ["static", "--version", version, "--profile", profile], out / "static" / key)
            statics[key] = static_assessment(raw, config, out / "build/analysis" / key)
            save(out / "static" / key / "assessment.json", statics[key])
            print("static", key, raw["status"], flush=True)
    sealed = {str(p.relative_to(out)): digest(p) for p in sorted((out / "static").rglob("*")) if p.is_file()}
    save(out / "static-seal.json", {"sealed_at": timestamp(), "files": sealed,
                                   "runtime_started": False, "graph_source": "UNMODIFIED_PINNED_PYCG"})
    instrumentation = {}
    for version in config["versions"]:
        raw = container_case(image, ["audit_control", "--version", version], out / "audit_control" / version)
        instrumentation[version] = raw.get("status") == "COMPLETE" and raw.get("is_arithmetic_scalar") and matching_audit(raw, require_library_stack=False)
    cases = []
    for version in config["versions"]:
        for profile in config["profiles"]:
            for input_kind in config["inputs"]:
                key = version + "/" + profile + "/" + input_kind
                raw = container_case(image, ["runtime", "--version", version, "--profile", profile, "--input", input_kind], out / "runtime" / key)
                assessed = runtime_assessment(raw, instrumentation_valid=bool(instrumentation[version]))
                save(out / "runtime" / key / "assessment.json", assessed)
                cases.append({"version": version, "profile": profile, "input": input_kind,
                              "worker_status": raw["status"], "result_repr": raw.get("result_repr"),
                              "error": raw.get("error"), **assessed,
                              "static": statics[version + "/" + profile],
                              "raw_result": "runtime/" + key + "/result.json",
                              "raw_sha256": digest(out / "runtime" / key / "result.json")})
                print("runtime", key, assessed["fault_witness"], flush=True)
    summary = {"schema_version": "level23-pilot-results-v1", "completed_at": timestamp(),
               "scope": config["evidence_scope"], "advisory": config["advisory"],
               "execution_kind": config["execution_kind"], "plan_sha256": digest(out / "plan.json"),
               "static_seal_sha256": digest(out / "static-seal.json"), "image": image,
               "runtime_case_count": len(cases), "static_case_count": len(statics),
               "analyzer_status_counts": dict(Counter(r["status"] for r in statics.values())),
               "api_path_counts": dict(Counter(r["api_path"]["status"] for r in statics.values())),
               "constructor_path_counts": dict(Counter(r["constructor_path"]["status"] for r in statics.values())),
               "witness_counts": dict(Counter(r["fault_witness"] for r in cases)),
               "instrumentation_controls": instrumentation, "cases": cases,
               "llm_calls": 0, "ai_superiority": "UNMEASURED", "vrr": "UNMEASURED",
               "product_vex": "under_investigation", "product_triage_delta": "UNMEASURED"}
    save(out / "summary.json", summary)
    seal = {str(p.relative_to(out)): digest(p) for p in sorted(out.rglob("*")) if p.is_file()}
    save(out / "seal.json", {"sealed_at": timestamp(), "files": seal})
    return summary


def verify(out):
    out = Path(out).resolve()
    verify_build(out)
    seal = read(out / "seal.json")
    for name, sha in seal["files"].items():
        if digest(out / name) != sha:
            raise ValueError("Sealed artifact changed: " + name)
    static_seal = read(out / "static-seal.json")
    for name, sha in static_seal["files"].items():
        if digest(out / name) != sha:
            raise ValueError("Static output changed after runtime: " + name)
    summary = read(out / "summary.json")
    config = read(out / "plan.json")["config"]
    controls = {}
    for version in config["versions"]:
        raw = read(out / "audit_control" / version / "result.json")
        controls[version] = bool(raw.get("status") == "COMPLETE" and raw.get("is_arithmetic_scalar")
                                 and matching_audit(raw, require_library_stack=False))
    if summary["instrumentation_controls"] != controls:
        raise ValueError("Instrumentation controls mismatch")
    expected = {(v, p, i) for v in config["versions"] for p in config["profiles"] for i in config["inputs"]}
    if {(r["version"], r["profile"], r["input"]) for r in summary["cases"]} != expected or len(summary["cases"]) != len(expected):
        raise ValueError("Runtime case matrix mismatch")
    for case in summary["cases"]:
        raw = read(out / case["raw_result"])
        if raw.get("status") == "COMPLETE" and (
                raw.get("library_version") != case["version"] or raw.get("environment", {}).get("python") != config["expected_python"]):
            raise ValueError("Version/environment provenance mismatch")
        if case["raw_sha256"] != digest(out / case["raw_result"]):
            raise ValueError("Raw result provenance mismatch")
        assessment = runtime_assessment(raw, instrumentation_valid=bool(summary["instrumentation_controls"][case["version"]]))
        if any(case.get(k) != value for k, value in assessment.items()):
            raise ValueError("Runtime assessment mismatch")
        static_key = case["version"] + "/" + case["profile"]
        assessed = static_assessment(read(out / "static" / static_key / "result.json"), config, out / "build/analysis" / static_key)
        if assessed != case["static"]:
            raise ValueError("Static assessment mismatch")
    statics = [read(out / "static" / v / p / "assessment.json") for v in config["versions"] for p in config["profiles"]]
    counts = {"runtime_case_count": len(expected), "static_case_count": len(statics),
              "analyzer_status_counts": dict(Counter(r["status"] for r in statics)),
              "api_path_counts": dict(Counter(r["api_path"]["status"] for r in statics)),
              "constructor_path_counts": dict(Counter(r["constructor_path"]["status"] for r in statics)),
              "witness_counts": dict(Counter(r["fault_witness"] for r in summary["cases"]))}
    if any(summary.get(k) != value for k, value in counts.items()):
        raise ValueError("Aggregate count mismatch")
    first_runtime = min(read(p)["started_at"] for p in (out / "runtime").rglob("process.json"))
    if static_seal["sealed_at"] >= first_runtime:
        raise ValueError("Static seal must precede runtime observations")
    return {"status": "VERIFIED", "seal_sha256": digest(out / "seal.json"),
            "runtime_cases": len(expected), "static_cases": len(config["versions"]) * len(config["profiles"]),
            "scope": "Integrity and independent re-assessment; not human gold review or a general accuracy estimate"}

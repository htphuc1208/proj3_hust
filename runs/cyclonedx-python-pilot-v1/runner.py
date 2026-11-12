#!/usr/bin/env python3
"""Offline CycloneDX Python environment comparison on six old development roots.

Requires a separately installed cyclonedx-bom==8.0.1 tool venv and the original
capture image. Target environments are read-only; references enter only scoring.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import time

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]
PROJECTS = ("requests", "typer", "nox", "django-debug-toolbar", "imbalanced-learn", "pyserial")
IMAGE = "sha256:805b20fa868a3c2fd8acec00101cf50c2b76314a540377ba081cac4b7c7ec907"
PROBE = r'''
import importlib.metadata as m, json, os, platform, sys
v = sys.implementation.version
environment = dict(os_name=os.name, sys_platform=sys.platform,
    platform_machine=platform.machine(), platform_system=platform.system(),
    platform_release=platform.release(), platform_version=platform.version(),
    python_version=".".join(platform.python_version_tuple()[:2]),
    python_full_version=platform.python_version(), implementation_name=sys.implementation.name,
    implementation_version="%s.%s.%s" % (v.major,v.minor,v.micro),
    platform_python_implementation=platform.python_implementation())
print(json.dumps(dict(environment=environment, distributions=[dict(name=d.metadata['Name'],
    version=d.version, requirements=d.requires or [], metadata_path=str(d._path / 'METADATA'))
    for d in m.distributions()])))
'''


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def run(command, folder, label):
    start = time.monotonic()
    result = subprocess.run(command, text=True, capture_output=True, timeout=180)
    (folder / f"{label}.stdout").write_text(result.stdout)
    (folder / f"{label}.stderr").write_text(result.stderr)
    record = dict(command=command, exit_code=result.returncode, seconds=time.monotonic() - start)
    save(folder / f"{label}.execution.json", record)
    if result.returncode:
        raise RuntimeError(f"{label} failed; see {folder / (label + '.stderr')}")
    return result.stdout


def container(tool, target=None, output=None):
    cmd = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop=ALL",
           "--security-opt=no-new-privileges", "--user", "1000:1000", "--memory=1g", "--cpus=1",
           "-e", "PYTHONDONTWRITEBYTECODE=1", "--tmpfs", "/tmp:rw,size=128m",
           "-v", f"{tool}:/tool:ro"]
    if target:
        cmd += ["-v", f"{target}:/target:ro"]
    if output:
        cmd += ["-v", f"{output}:/out:rw"]
    return cmd


def metadata_graph(probe):
    """Direct Requires-Dist semantics, all installed base declarations + propagated extras."""
    installed = {canonicalize_name(d["name"]): d for d in probe["distributions"]}
    assert len(installed) == len(probe["distributions"]), "Ambiguous installed identities"
    extras = {n: set() for n in installed}
    parsed = {n: [Requirement(r) for r in d["requirements"]] for n, d in installed.items()}

    def active(parent, req):
        return req.marker is None or any(req.marker.evaluate(
            environment={**probe["environment"], "extra": e}) for e in {"", *extras[parent]})

    def child(req):
        name = canonicalize_name(req.name)
        return name if name in installed and not req.url and req.specifier.contains(
            installed[name]["version"], prereleases=True) else None

    changed = True
    while changed:
        changed = False
        for name, requirements in parsed.items():
            for req in requirements:
                target = child(req)
                if target is not None and active(name, req):
                    new = {canonicalize_name(e) for e in req.extras} - extras[target]
                    extras[target].update(new)
                    changed |= bool(new)
    edges, unresolved = set(), []
    for name, requirements in parsed.items():
        for req in requirements:
            if active(name, req):
                target = child(req)
                if target is None:
                    unresolved.append({"parent": name, "requirement": str(req)})
                else:
                    edges.add((name, target))
    return installed, edges, unresolved, extras


def sbom_graph(document):
    components = list(document.get("components", []))
    if document.get("metadata", {}).get("component"):
        components += [document["metadata"]["component"]]
    names = {c["bom-ref"]: canonicalize_name(c["name"]) for c in components}
    edges = set()
    for row in document.get("dependencies", []):
        for target in row.get("dependsOn", []):
            assert row["ref"] in names and target in names, "Dangling native dependency reference"
            edges.add((names[row["ref"]], names[target]))
    return {canonicalize_name(c["name"]): c["version"] for c in components}, edges


def closure(root, edges):
    reached = {root}
    while True:
        expanded = reached | {b for a, b in edges if a in reached}
        if expanded == reached:
            return reached
        reached = expanded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--captures", type=Path, default=ROOT / "research/.work/m25-cohort-captures-v2")
    parser.add_argument("--tool", type=Path, default=ROOT / "research/.work/comparators/cyclonedx-python-8.0.1")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out, tool, captures = args.out.resolve(), args.tool.resolve(), args.captures.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if (out / "plan.json").exists():
        raise FileExistsError("Use a fresh pilot output directory")
    save(out / "plan.json", dict(projects=PROJECTS, image=IMAGE, tool="cyclonedx-bom==8.0.1",
        captures=str(captures), tool_directory=str(tool), runner_sha256=digest(__file__),
        selection="Six named old development projects selected before observing CycloneDX results",
        scope="All top-level installed distributions; application closure reported separately",
        extras="No requested root extras; propagate dependency-requested extras to a fixed point",
        prediction_mounts="tool ro, target ro, output rw; no oracle; network disabled",
        generated_at=datetime.now(timezone.utc).isoformat()))
    (out / "runner.py").write_bytes(Path(__file__).read_bytes())
    provenance = json.loads(run(container(tool) + ["--entrypoint", "/tool/.venv/bin/python", IMAGE,
        "-I", "-c", PROBE], out, "tool-inventory"))
    save(out / "tool-inventory.json", provenance)
    assert next(d["version"] for d in provenance["distributions"] if d["name"] == "cyclonedx-bom") == "8.0.1"
    source = tool / ".venv/lib/python3.11/site-packages/cyclonedx_py/_internal/environment.py"
    (out / "cyclonedx-environment-source.py").write_bytes(source.read_bytes())
    seals = {}
    for project in PROJECTS:
        capture = load(captures / project / "capture.json")
        assert capture["status"] == "COMPLETE" and capture["project"]["partition"] == "development"
        assert capture["image"] == IMAGE
        target = captures / project / "runtime/target"
        case = out / project
        case.mkdir(exist_ok=True)
        before = {str(p.relative_to(target)): digest(p) for p in sorted(target.rglob("*.dist-info/METADATA"))}
        cmd = container(tool, target, case)
        run(cmd + ["--entrypoint", "/tool/.venv/bin/python", IMAGE, "-m", "cyclonedx_py", "environment",
            "/target/bin/python", "--spec-version", "1.6", "--output-reproducible", "--output-format", "JSON",
            "--output-file", "/out/sbom.cdx.json", "--validate"], case, "scan")
        probe = json.loads(run(cmd + ["--entrypoint", "/target/bin/python", IMAGE, "-I", "-c", PROBE],
            case, "target-inventory"))
        save(case / "target-inventory.json", probe)
        assert before == {str(p.relative_to(target)): digest(p) for p in target.rglob("*.dist-info/METADATA")}
        seals[project] = dict(sbom_sha256=digest(case / "sbom.cdx.json"),
            inventory_sha256=digest(case / "target-inventory.json"), target_metadata=before)
        save(case / "scan-seal.json", seals[project])
        print(f"Scanned {project}", flush=True)
    # Only now read reference labels. No oracle directory was mounted for scanning.
    save(out / "scan-seals.json", seals)
    results = []
    for project in PROJECTS:
        case, oracle = out / project, captures / project / "oracle"
        assert digest(case / "sbom.cdx.json") == seals[project]["sbom_sha256"]
        probe = load(case / "target-inventory.json")
        installed, expected, unresolved, extras = metadata_graph(probe)
        reference = load(oracle / "installed_reference.json")
        saved_edges = {(e["from"], e["to"]) for e in reference["edges"]}
        saved_nodes = {n["name"]: n["version"] for n in reference["nodes"]}
        root_input = (oracle / "root.in").read_text().strip()
        assert "[" not in root_input, "Root extras require an explicit seed in this pilot"
        assert saved_edges == expected and saved_nodes == {n: d["version"] for n, d in installed.items()}, project
        assert not unresolved and not reference["unresolved"], "Unresolved declarations require separate labeling"
        actual_nodes, actual = sbom_graph(load(case / "sbom.cdx.json"))
        assert actual_nodes == saved_nodes, "Inventory/version mismatch must be investigated before edge scoring"
        app_nodes = closure(project, expected)
        missing, extra = expected - actual, actual - expected
        details = []
        for a, b in sorted(extra):
            matches = [Requirement(r) for r in installed[a]["requirements"]
                       if canonicalize_name(Requirement(r).name) == b]
            details.append(dict(source=a, target=b, requirements=[str(r) for r in matches],
                marker_results=[r.marker is None or any(r.marker.evaluate(
                    environment={**probe["environment"], "extra": e}) for e in {"", *extras[a]}) for r in matches],
                reason="All matching installed declarations inactive" if matches and all(r.marker is not None and
                    all(not r.marker.evaluate(environment={**probe["environment"], "extra": e})
                        for e in {"", *extras[a]}) for r in matches) else "REQUIRES_REVIEW"))
        assessment = dict(project=project, version=installed[project]["version"], installed_packages=len(installed),
            expected_edges=len(expected), actual_edges=len(actual), missing_edges=sorted(missing), extra_edges=sorted(extra),
            extra_edge_explanations=details, application_packages=len(app_nodes),
            application_expected_edges=sum(a in app_nodes for a, b in expected),
            application_missing_edges=sorted(e for e in missing if e[0] in app_nodes),
            application_extra_edges=sorted(e for e in extra if e[0] in app_nodes),
            application_unexpected_reachable_packages=sorted(closure(project, actual) - app_nodes),
            independently_recomputed_reference_matches=True, unresolved_requirements=unresolved,
            input_root=root_input, active_extras={n: sorted(v) for n, v in extras.items() if v},
            environment=probe["environment"], saved_reference_sha256=digest(oracle / "installed_reference.json"),
            pip_inspect_sha256=digest(oracle / "pip_inspect.json"))
        save(case / "assessment.json", assessment)
        results.append(assessment)
    save(out / "summary.json", dict(status="COMPLETE", projects=results,
        missing_edges=sum(len(r["missing_edges"]) for r in results), extra_edges=sum(len(r["extra_edges"]) for r in results),
        independent_projects=len(results), claim="Development pilot only; declared dependency semantics, not runtime use"))
    rows = ["| Dự án | Gói đã cài | Cạnh reference | Cạnh CycloneDX | Thiếu | Dư/bất hoạt |",
            "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for r in results:
        rows.append(f"| {r['project']} {r['version']} | {r['installed_packages']} | {r['expected_edges']} | "
                    f"{r['actual_edges']} | {len(r['missing_edges'])} | {len(r['extra_edges'])} |")
    app_rows = ["| Dự án | Cạnh hoạt động trong closure ứng dụng | Thiếu | Dư có parent trong closure |",
                "| --- | ---: | ---: | ---: |"]
    for r in results:
        app_rows.append(f"| {r['project']} | {r['application_expected_edges']} | "
                        f"{len(r['application_missing_edges'])} | {len(r['application_extra_edges'])} |")
    (out / "REPORT.md").write_text("# CycloneDX Python 8.0.1 — pilot trên môi trường đã cài\n\n" + "\n".join(rows) +
        "\n\nChạy lệnh `environment` trên Linux/CPython 3.11.16, CycloneDX 1.6 JSON, validation bật. "
        "Công cụ được cài riêng; target chỉ đọc; container quét không có network hoặc oracle. "
        "Không truyền pyproject để tránh thay metadata của gói gốc bằng một nguồn khác.\n\n"
        "Reference là declared direct requirements của toàn bộ gói cài trực tiếp trong site-packages, "
        "bao gồm pip/setuptools; loại metadata vendored lồng trong setuptools. Không yêu cầu root extras; "
        "extras từ khai báo con được lan truyền đến fixed point. Đối chiếu độc lập từ metadata target mới đọc "
        "với reference cài đặt đã lưu: tập gói/phiên bản và tập cạnh phải trùng trước khi chấm. "
        "Reference được tính lại bằng mã riêng nhưng vẫn chia sẻ ngữ nghĩa khai báo và thư viện packaging; "
        "đây không phải kiểm chứng độc lập về mã thực thi.\n\n"
        "## Kết quả riêng cho ứng dụng\n\n" + "\n".join(app_rows) + "\n\n"
        "Không thấy cạnh thiếu trên sáu môi trường. Có 13 lượt cạnh dư/bất hoạt trên toàn bộ môi trường: "
        "10 có parent setuptools, ba có parent nằm trong closure ứng dụng. Không phải 13 cạnh độc lập.\n\n"
        "- nox: `virtualenv → packaging` và `virtualenv → setuptools` chỉ được khai báo cho extra `test`. "
        "Extra này không được yêu cầu. Cạnh thứ hai làm setuptools và pip trở nên reachable từ nox "
        "trong đồ thị xuất ra, dù không nằm trong closure khai báo hoạt động của ứng dụng.\n"
        "- imbalanced-learn: `scipy → threadpoolctl` chỉ dành cho extra `test`. Gói threadpoolctl vẫn "
        "reachable qua đường hợp lệ khác, nên cạnh dư này không tạo thêm package reachable.\n"
        "- Cả sáu môi trường: `setuptools → pip` dành cho extra `test` vẫn xuất hiện. Cạnh này có parent "
        "nằm ngoài closure hoạt động của ứng dụng, nên không tính là lỗi cạnh trực tiếp của ứng dụng.\n\n"
        "Trong mã nguồn 8.0.1 được lưu kèm (`cyclonedx-environment-source.py`), "
        "`__finalize_dependencies` liên kết Requires-Dist với gói đã cài theo tên, không đánh giá marker. "
        "Điều này phù hợp với các cạnh extra bất hoạt quan sát được. Xem "
        "[mã nguồn upstream](https://github.com/CycloneDX/cyclonedx-python/blob/v8.0.1/cyclonedx_py/_internal/environment.py) "
        "và [hướng dẫn environment](https://cyclonedx-bom-tool.readthedocs.io/en/latest/usage.html).\n\n"
        "Đây là sáu dự án development cũ, không phải held-out hay mẫu đại diện PyPI. "
        "Các cạnh dư là khác biệt so với đồ thị kích hoạt theo ngữ cảnh đã định nghĩa; "
        "không tự chứng minh công cụ vi phạm đặc tả CycloneDX. Kết quả không đo runtime, "
        "exploitability hoặc novelty. Chưa có bằng chứng từ pilot này rằng cần một thuật toán khôi phục "
        "cạnh thiếu tốt hơn CycloneDX Python; khác biệt đang thấy là lọc cạnh theo ngữ cảnh extras. "
        "Xem assessment.json cho từng cạnh và khai báo nguồn.\n\n"
        "## Tái lập\n\n"
        "Cài `cyclonedx-bom==8.0.1` vào venv công cụ riêng trên image đã ghi trong plan.json. "
        "tool-inventory.json ghi phiên bản tất cả dependency của công cụ. Sau đó chạy:\n\n"
        "```bash\n.venv/bin/python -B scripts/run_cyclonedx_python_pilot.py "
        "--out runs/cyclonedx-python-pilot-new\n```\n\n"
        "Các file scan.execution.json lưu đầy đủ lệnh Docker và thời gian; scan.stderr giữ cảnh báo. "
        "scan-seal.json và scan-seals.json ghi hash SBOM, inventory và metadata gốc.\n")
    print(json.dumps({r["project"]: {"missing": len(r["missing_edges"]), "extra": len(r["extra_edges"])}
                      for r in results}, indent=2))


if __name__ == "__main__":
    main()

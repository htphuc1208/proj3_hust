#!/usr/bin/env python3
"""Pinned contemporary-tool DSN subset plus separately evaluated operational B4."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from research_core import (RunBundle, components, digest, graph, load, normalize_sbom, now, save, score_application, score_sets)
from research_baselines import b4_from_report
from container_runner import run_container
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


def author_labels(path):
    labels = set()
    notes = []
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        req = Requirement(line)
        version = next((s.version for s in req.specifier if s.operator == "=="), None)
        if not version and req.url:
            # Published direct-URL names do not carry versions. Parse wheel/archive
            # filenames explicitly; do not use a contemporary registry lookup as the label.
            from packaging.utils import parse_wheel_filename, parse_sdist_filename
            from urllib.parse import urlparse, unquote
            filename = unquote(urlparse(req.url).path).split("/")[-1]
            try:
                version = str(parse_wheel_filename(filename)[1]) if filename.endswith(".whl") else str(parse_sdist_filename(filename)[1])
            except Exception:
                from packaging.version import Version, InvalidVersion
                try:
                    version = str(Version(filename.removesuffix(".zip")))
                except InvalidVersion:
                    notes.append({"line": line, "status": "LABEL_IDENTITY_UNRESOLVED"})
        if version:
            labels.add(f"pkg:pypi/{canonicalize_name(req.name)}@{version}")
    return labels, notes


def run(out, ablation):
    out = Path(out).resolve()
    bundle = RunBundle(out, out.name, purpose="Partial DSN 2024 reproduction and B4 validation", data_kind="AUTHORED_METADATA_BENCHMARK")
    lock = load(ROOT / "research/toolchain.json")
    source = ROOT / "research/.work/sbom-benchmark"
    metadata = load(ROOT / "research/papers/dsn2024.json")
    actual = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if actual != metadata["benchmark_commit"]:
        bundle.finish("BLOCKED", technical_cause="Benchmark checkout commit mismatch")
        raise ValueError("Benchmark checkout commit mismatch")
    bundle.artifact("paper.json", metadata)
    bundle.artifact("toolchain.json", lock)
    published, notes = author_labels(source / "python/req/groundtruth")
    bundle.copy("authors_groundtruth.txt", source / "python/req/groundtruth")
    cases = {}
    # Positive parser control distinguishes unsupported original metadata from a broken scanner invocation.
    control = ROOT / "research/.work" / out.name / "positive-control"
    control.mkdir(parents=True, exist_ok=True)
    (control / "requirements.txt").write_text("requests==2.31.0\n")
    controls = {}
    for scanner in ("syft", "trivy"):
        binary = str(ROOT / "research/.work" / scanner)
        command = [binary, "scan", "dir:" + str(control), "-o", "cyclonedx-json"] if scanner == "syft" else [
            binary, "fs", "--format", "cyclonedx", "--skip-db-update", "--skip-java-db-update", "--offline-scan", str(control)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=180,
                                env={**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false"})
        import json
        raw = json.loads(result.stdout) if result.returncode == 0 else {}
        identities = sorted(c["purl"] for c in components(raw) if c.get("purl", "").startswith("pkg:pypi/"))
        controls[scanner] = {"data_kind": "SYNTHETIC_PARSER_CONTROL", "command": command,
                             "exit_code": result.returncode, "identities": identities}
        bundle.artifact(f"positive_control/{scanner}.cdx.json", raw)
        bundle.artifact(f"positive_control/{scanner}_execution.json", {"stderr": result.stderr, "input": "requests==2.31.0"})
    bundle.artifact("scanner_positive_controls.json", controls)
    for entrypoint in ("requirements.txt", "r.txt"):
        case_id = entrypoint.replace(".txt", "")
        workspace = ROOT / "research/.work" / out.name / case_id
        workspace.mkdir(parents=True, exist_ok=False)
        selected = [entrypoint, "const.txt"] + (["otherreq.txt"] if entrypoint == "requirements.txt" else [])
        for name in selected:
            shutil.copyfile(source / "python/req" / name, workspace / name)
            bundle.copy(f"{case_id}/input/{name}", workspace / name)
        if entrypoint == "requirements.txt":
            shutil.copytree(source / "python/req/downloads", workspace / "downloads")
            for p in (workspace / "downloads").rglob("*"):
                if p.is_file():
                    bundle.copy(f"{case_id}/input/downloads/{p.relative_to(workspace / 'downloads')}", p)
        case = {"entrypoint": entrypoint, "input_policy": "Original selected entrypoint plus referenced files; author groundtruth and other entrypoint NOT visible to scanners",
                "data_kind": "AUTHORED_METADATA_BENCHMARK", "scanners": {}, "source_commit": actual,
                "input_hashes": {str(p.relative_to(workspace)): digest(p) for p in workspace.rglob("*") if p.is_file()}}
        for scanner in ("syft", "trivy"):
            binary = ROOT / "research/.work" / scanner
            if digest(binary) != lock["tools"][scanner]["binary_sha256"]:
                raise ValueError("Scanner binary changed after freeze")
            if scanner == "syft":
                command = [str(binary), "scan", f"dir:{workspace}", "-o", "cyclonedx-json"]
            else:
                command = [str(binary), "fs", "--format", "cyclonedx", "--skip-db-update", "--skip-java-db-update",
                           "--offline-scan", "--skip-check-update", str(workspace)]
            started, t = now(), time.monotonic()
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=180,
                    env={**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false", "TRIVY_OFFLINE_SCAN": "true"})
                (out / case_id / (scanner + ".log")).write_text(result.stderr)
                if result.returncode:
                    raise RuntimeError(result.stderr)
                (out / case_id / (scanner + ".cdx.json")).write_text(result.stdout)
                import json
                raw = json.loads(result.stdout)
                observed = {c["purl"].split("?", 1)[0] for c in components(raw) if c.get("purl", "").startswith("pkg:pypi/")}
                case["scanners"][scanner] = {"status": "RAN", "component_count": len(observed), "components": sorted(observed),
                    "author_label_agreement": score_sets(published, observed) if entrypoint == "requirements.txt" else None,
                    "label_scope": "Archived authors' full requirements.txt component/version labels only" if entrypoint == "requirements.txt" else "No released per-entrypoint label; no invented precision/recall",
                    "dependency_edge_metrics": "UNMEASURED; authors' component list has no direct-edge labels",
                    "command": command, "started_at": started, "completed_at": now(), "latency_seconds": time.monotonic() - t,
                    "output_sha256": digest(out / case_id / (scanner + ".cdx.json"))}
            except Exception as exc:
                case["scanners"][scanner] = {"status": "BLOCKED", "technical_cause": str(exc), "command": command}
        # Isolated attempts use literal public author inputs. Do not patch obsolete
        # requirements to make a contemporary install appear reproducible.
        attempts = {}
        for name, pip_args in [("b4", ["--dry-run", "--ignore-installed", "--report", "/out/resolution.json"]),
                               ("independent_install", ["--target", "/tmp/target", "--report", "/out/installation.json"])]:
            destination = out / case_id / name
            destination.mkdir()
            command = ["docker", "run", "--rm", "--cap-drop=ALL", "--security-opt", "no-new-privileges", "--memory=2g", "--cpus=2",
                       "--pids-limit=128", "--user", "1000:1000", "-v", f"{workspace}:/source:ro", "-v", f"{destination}:/out:rw",
                       "--workdir", "/source", "--entrypoint", "python", lock["image"], "-m", "pip", "install", *pip_args,
                       "-r", entrypoint]
            if name == "independent_install":
                code = ROOT / "research/.work" / out.name / "install_code"
                code.mkdir(exist_ok=True)
                for source_file in (ROOT / "benchmark.py", ROOT / "scripts/attempt_dsn_install.py"):
                    shutil.copyfile(source_file, code / source_file.name)
                command = ["docker", "run", "--rm", "--cap-drop=ALL", "--security-opt", "no-new-privileges", "--memory=2g", "--cpus=2",
                    "--pids-limit=128", "--user", "1000:1000", "-v", f"{workspace}:/source:ro", "-v", f"{destination}:/out:rw",
                    "-v", f"{code}:/code:ro", "--workdir", "/source", "--entrypoint", "python", lock["image"],
                    "/code/attempt_dsn_install.py", entrypoint]
            try:
                result = run_container(command, timeout=600)
                (destination / "execution.log").write_text(result.stdout + result.stderr)
                attempts[name] = {"status": "RAN" if result.returncode == 0 else "BLOCKED", "exit_code": result.returncode,
                                  "command": command, "log_sha256": digest(destination / "execution.log"),
                                  "comparison_eligibility": "NONCOMPARABLE_TO_HISTORICAL_INSTALLATION; live index not a 2024 snapshot"}
            except subprocess.TimeoutExpired:
                attempts[name] = {"status": "BLOCKED", "technical_cause": "600-second resource limit", "command": command}
        case["installation_attempts"] = attempts
        gold_path = out / case_id / "independent_install/ground_truth.json"
        if gold_path.exists():
            fresh_gold = load(gold_path)
            fresh_nodes = {n["purl"] for n in fresh_gold["nodes"]}
            for record in case["scanners"].values():
                if record["status"] == "RAN":
                    record["fresh_installed_component_score"] = score_sets(fresh_nodes, set(record["components"]))
                    record["fresh_reference_caveat"] = "Contemporary live-index installation; not the authors' 2024 environment"
            for scanner, record in case["scanners"].items():
                if record["status"] == "RAN":
                    normalized, scope = normalize_sbom(load(out / case_id / (scanner + ".cdx.json")))
                    record["fresh_installed_edge_evaluation"] = score_application(fresh_gold, set(), graph(normalized)[1], scope)
            case["fresh_reference"] = {"nodes": len(fresh_nodes), "edges": len(fresh_gold["edges"]),
                                       "unresolved_requirements": len(fresh_gold["unresolved"]), "sha256": digest(gold_path)}
        case["reproduction_status"] = "PARTIALLY_REPRODUCED" if any(s["status"] == "RAN" for s in case["scanners"].values()) else "BLOCKED"
        cases[case_id] = case
        bundle.artifact(case_id + "/result.json", case)
    b4_results = {}
    for name in ("base", "socks"):
        capture = Path(ablation) / name
        manifest = load(capture / "capture_manifest.json")
        # Only B4 report and declared roots enter prediction, oracle is read afterwards.
        prediction = b4_from_report(load(capture / "b4_resolution.json"), manifest["specifications"])
        gold = load(capture / "ground_truth.json")
        original, scope = normalize_sbom(load(capture / "original.cdx.json"), "requests", bootstrap=("pip", "setuptools"))
        score = score_application(gold, set(), {tuple(e) for e in prediction["predicted_edges"]}, scope)
        truth_nodes = {n["purl"] for n in gold["nodes"]}
        b4_results[name] = {"prediction": prediction, "edge_evaluation": score,
            "component_evaluation": score_sets(truth_nodes, set(prediction["predicted_nodes"])),
            "reference_source": "Separate installed-environment METADATA capture",
            "oracle_sha256": digest(capture / "ground_truth.json"), "resolution_sha256": digest(capture / "b4_resolution.json"),
            "wheelhouse_manifest": load(capture / "wheelhouse_manifest.json"),
            "cost": next(c for c in manifest["commands"] if c["name"] == "b4_dry_run")}
    bundle.artifact("b4_comparison.json", b4_results)
    bundle.artifact("reproduction_results.json", {"status": "PARTIALLY_REPRODUCED", "paper": metadata,
        "cases": cases, "author_label_count": len(published), "unresolved_author_labels": notes,
        "scanner_positive_controls": controls,
        "claim_limit": "Contemporary-tool authored subset only. No reproduction of original population statistics or dependency-edge ground truth."})
    bundle.finish("PARTIALLY_REPRODUCED")
    print(out)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--ablation-run", type=Path, required=True)
    a = p.parse_args()
    run(a.out, a.ablation_run)

"""Pinned upstream code adapters. Never reimplement or silently fix the baseline."""
from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
import csv
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys

from research_core import digest, load, save
from .storage import save

UNIFIER_COMMIT = "521f3b8ee6e301e847f7cb113517ba46831e2b28"
REPLICATION_COMMIT = "5b90367e247fced49fbf73d831f4e53b2aa45819"
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "research/.work"


def upstream(path, expected):
    path = Path(path).resolve()
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=path, text=True)
    if actual != expected or dirty:
        raise ValueError("Upstream commit mismatch or modified tracked source: " + str(path))
    return path


def analyzer(replication=None):
    path = upstream(replication or WORK / "sbom-unifier-replication", REPLICATION_COMMIT)
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
    import sbom_analyzer
    if Path(sbom_analyzer.__file__).resolve().parent != path / "sbom_analyzer":
        raise ValueError("Unexpected analyzer import")
    return sbom_analyzer


def coverage(document, replication=None):
    if not str(document.get("spdxVersion", "")).startswith("SPDX-2."):
        raise ValueError("Coverage comparison requires native SPDX; no implicit conversion")
    a = analyzer(replication)
    raw = a.analyze_sbom(document)
    output = {}
    for scope, allowed in (("required", {"required"}), ("required+optional", {"required", "optional"})):
        counts = {"full": 0, "part": 0, "miss": 0}
        for section, display, _, _, category in a.SPDX_FIELDS:
            if category not in allowed:
                continue
            value = raw[f"{section}|{display}"]
            if value in ("NOASSERTION", "NONE"):
                value = "miss"
            if value in counts:
                counts[value] += 1
        total = sum(counts.values())
        output[scope] = {**counts, "evaluated_fields": total,
                         **{k + "_pct": round(v / total * 100, 2) for k, v in counts.items()}}
    return {"upstream_commit": REPLICATION_COMMIT, "scopes": output, "raw_fields": raw,
            "interpretation": "Field presence only; NONE counts as populated in the upstream analyzer"}


def merge(documents, source_dir=None, unifier=None):
    if not documents:
        raise ValueError("At least one native SPDX input required")
    if any(not d.get("spdxVersion") for _, d in documents):
        raise ValueError("sbom-unifier inputs must be native SPDX")
    path = upstream(unifier or WORK / "sbom-unifier", UNIFIER_COMMIT)
    if str(path / "src") not in sys.path:
        sys.path.insert(0, str(path / "src"))
    from sbom_unifier.merge.merger import finalize_sbom, merge_sbom
    from sbom_unifier.enrichment import enrich_sbom
    import sbom_unifier
    if Path(sbom_unifier.__file__).resolve().parent != path / "src/sbom_unifier":
        raise ValueError("Unexpected baseline import")
    base = deepcopy(documents[0][1])
    log = io.StringIO()
    old_path = os.environ.get("PATH", "")
    if source_dir:
        os.environ["PATH"] = str(WORK / "tool-bin") + os.pathsep + old_path
    try:
        with redirect_stdout(log):
            stats = [{"source": name, "result": merge_sbom(base, doc, name)} for name, doc in documents[1:]]
            if source_dir:
                source_root = Path(source_dir).resolve()
                for entry in base.get("files", []):
                    raw_name = entry.get("fileName", "")
                    rel = raw_name[2:] if raw_name.startswith("./") else raw_name.lstrip("/")
                    if not (source_root / rel).resolve().is_relative_to(source_root):
                        raise ValueError("Source enrichment path escapes the declared snapshot")
            enrichment = enrich_sbom(base, str(source_dir) if source_dir else None)
            finalize_sbom(base)
    finally:
        os.environ["PATH"] = old_path
    return base, {"commit": UNIFIER_COMMIT, "merge_order": [n for n, _ in documents],
                  "merge_results": stats, "enrichment": enrichment, "stdout": log.getvalue(),
                  "scope": "NATIVE_SPDX_MERGE_AND_ENRICHMENT", "source_dir_supplied": source_dir is not None}


def reproduce(destination, replication=None):
    """Call the original functions with a fresh output root; preserve the reference CSVs."""
    path = upstream(replication or WORK / "sbom-unifier-replication", REPLICATION_COMMIT)
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    analyzer(path)
    spec = importlib.util.spec_from_file_location("sbom_unifier_upstream_reproduction", path / "reproduce.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.OUT_DIR = destination
    # The upstream writer prints relative paths. ROOT controls printing only; SBOM_DIR is frozen above.
    import os
    module.ROOT = Path(os.path.commonpath([path, destination]))
    with (destination / "reproduction.log").open("w") as log, redirect_stdout(log):
        module.main()
    comparison = {}
    for name in ("coverage_overall.csv", "coverage_by_language.csv", "field_coverage_by_project.csv", "spdx_fields.csv"):
        original = path / "analysis_results" / name
        produced = destination / name
        comparison[name] = {"expected_sha256": digest(original), "actual_sha256": digest(produced),
                            "byte_identical": original.read_bytes() == produced.read_bytes()}
    rows = list(csv.DictReader((destination / "field_coverage_by_project.csv").open()))
    result = {"status": "REPRODUCED" if all(r["byte_identical"] for r in comparison.values()) else "MISMATCH",
              "replication_commit": REPLICATION_COMMIT, "unifier_commit": UNIFIER_COMMIT,
              "project_count": len({(r["language"], r["project"]) for r in rows}), "rows": len(rows),
              "files": comparison, "correctness_metrics": "UNMEASURED", "llm_api_calls": 0}
    save(destination / "verification.json", result)
    return result

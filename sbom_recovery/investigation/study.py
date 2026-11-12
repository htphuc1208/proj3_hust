"""Frozen paired experiments with scorer-only labels and staged inference.

Inference runs in another process with only public bundle files named in its
configuration. A Python audit hook limits accidental reads and subprocess use;
this is defense in depth, not an OS security sandbox for hostile Python code.
Every prediction is sealed before the controller opens any oracle bytes.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
from typing import Literal

from pydantic import Field, model_validator

from sbom_recovery.core.contracts import StrictModel
from sbom_recovery.reconciliation.contracts_v3 import BlobReferenceV3
from sbom_recovery.reconciliation.merge_contracts_v3 import ReconciliationRequestV3

from .evidence import EvidenceCatalog, read_frozen_blob
from .models import Budget


METHODS = {"observed", "deterministic", "rule", "metadata_only", "graph_only", "agent", "fixed_llm", "sbom_unifier"}
ROOT = Path(__file__).resolve().parents[2]


class StudyCase(StrictModel):
    case_id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    project: str = Field(min_length=1)
    lineage: str = Field(min_length=1)
    split: Literal["development", "test"]
    request: BlobReferenceV3
    oracle: BlobReferenceV3
    snapshot: BlobReferenceV3 | None = None
    advisory_ids: list[str] | None = None


class StudyManifest(StrictModel):
    schema_version: Literal["investigation-study-v1"]
    cases: list[StudyCase] = Field(min_length=1)
    methods: list[str] = Field(min_length=1)
    budget: Budget = Field(default_factory=Budget)
    conditions: list[Literal["equal_budget", "equal_information"]] = Field(default_factory=lambda: ["equal_budget"])
    model: str | None = None
    model_base_url: str | None = None
    seed: int = 11
    bootstrap_samples: int = Field(default=2000, ge=1, le=100000)
    label_kind: str | None = None
    advisory_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def frozen_arms(self):
        supported = METHODS | {"naive_union", "fixed_priority", "majority", "lockfile_only"}
        if len(self.methods) != len(set(self.methods)) or any(m not in supported and not re.fullmatch(r"single:[A-Za-z0-9][A-Za-z0-9_.-]*", m) for m in self.methods):
            raise ValueError("Study methods must be unique supported method names")
        if len(self.conditions) != len(set(self.conditions)) or not self.conditions:
            raise ValueError("Study conditions must be nonempty and unique")
        ids = [c.case_id for c in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate case IDs")
        # Duplicating the same release under different case IDs does not create
        # independent project evidence or an extra test case.
        requests = [c.request.sha256 for c in self.cases]
        if len(requests) != len(set(requests)):
            raise ValueError("Duplicate request bytes across cases")
        if set(self.methods).intersection({"agent", "fixed_llm"}):
            if not self.model or self.budget.input_usd_per_million is None:
                raise ValueError("LLM arms require a frozen model identifier and input/output prices")
        for ids in [self.advisory_ids] + [c.advisory_ids for c in self.cases if c.advisory_ids is not None]:
            if any(not value for value in ids) or len(ids) != len(set(ids)):
                raise ValueError("Focused advisory IDs must be nonempty and unique")
        return self


def _write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _read_oracle(base, blob):
    """Scorer-only loader; oracle path names are allowed, symlinks are not."""
    # BlobReferenceV3 has already rejected traversal, absolute and empty parts.
    descriptors = []
    try:
        fd = os.open(Path(base).absolute(), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(fd)
        for part in blob.path.split("/")[:-1]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            descriptors.append(fd)
        fd = os.open(blob.path.split("/")[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        descriptors.append(fd)
        info = os.fstat(fd)
        limit = 32 * 1024 * 1024
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("Oracle must be a bounded regular file")
        pieces, size = [], 0
        while True:
            raw = os.read(fd, min(65536, limit + 1 - size))
            if not raw:
                break
            pieces.append(raw)
            size += len(raw)
            if size > limit:
                raise ValueError("Oracle exceeds byte limit")
        raw = b"".join(pieces)
        if _sha(raw) != blob.sha256:
            raise ValueError("Frozen oracle digest changed")
        return json.loads(raw)
    except OSError as exc:
        raise ValueError("Oracle unavailable or unsafe") from exc
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def _stage(case, base, destination):
    raw = read_frozen_blob(base, case.request.path, case.request.sha256, 4 * 1024 * 1024)
    request = ReconciliationRequestV3.model_validate_json(raw)
    source_prefix = Path(case.request.path).parent
    destination = Path(destination)
    destination.mkdir(parents=True)
    (destination / "request.json").write_bytes(raw)
    copied = {"request.json": case.request.sha256}
    blobs = [d.document for d in request.documents] + [e.blob for e in request.evidence]
    if request.target.artifact:
        blobs.append(request.target.artifact.artifact)
    if request.consumer:
        blobs += [request.consumer.configuration, request.consumer.advisory_snapshot]
    for blob in blobs:
        if blob.path in copied:
            if copied[blob.path] != blob.sha256:
                raise ValueError("A public path has contradictory frozen digests")
            continue
        combined = str(source_prefix / blob.path)
        value = read_frozen_blob(base, combined, blob.sha256, 32 * 1024 * 1024)
        path = destination / blob.path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        copied[blob.path] = blob.sha256
    return request, copied


def _verify_seal(folder, expected_seal_sha256):
    folder = Path(folder)
    seal_path = folder / "seal.json"
    if seal_path.is_symlink():
        raise ValueError("Prediction seal is a symlink")
    raw = seal_path.read_bytes()
    if _sha(raw) != expected_seal_sha256:
        raise ValueError("Prediction seal changed before scoring")
    seal = json.loads(raw)
    if seal.get("schema_version") != "investigation-seal-v1" or "prediction.json" not in seal.get("files", {}):
        raise ValueError("Prediction seal is incomplete")
    for name, expected in seal["files"].items():
        if not isinstance(name, str) or Path(name).name != name:
            raise ValueError("Unsafe artifact in prediction seal")
        read_frozen_blob(folder, name, expected, 64 * 1024 * 1024)
    return json.loads((folder / "prediction.json").read_text())


def _metrics(scored, prediction):
    counts = prediction.get("investigation", {})
    usage = counts.get("usage", {})
    flat = {key + "_f1": scored.get(key, {}).get("f1") for key in (
        "components", "candidate_components", "edges", "candidate_edges", "paths", "candidate_paths", "security", "candidate_security")}
    flat.update(verified_fraction=scored.get("coverage", {}).get("verified_fraction"),
                incorrect_correction_rate=scored.get("corrections", {}).get("incorrect_rate"),
                false_safe_rate=scored.get("security", {}).get("false_safe_rate"),
                scope_accuracy=scored.get("edge_scope", {}).get("accuracy"),
                tool_calls=usage.get("tool_calls", counts.get("tool_calls")), bytes=usage.get("bytes", counts.get("bytes_used")),
                duration_seconds=usage.get("seconds", counts.get("duration_seconds")))
    return flat


def _project_summary(rows):
    grouped = defaultdict(list)
    for row in rows:
        if row.get("status") == "SCORED":
            grouped[(row["project_id"], row["method"], row["condition"], row["split"])].append(row)
    results = []
    for (project, method, condition, split), group in sorted(grouped.items()):
        names = {name for row in group for name in row["metrics"]}
        metrics = {}
        for name in sorted(names):
            values = [row["metrics"].get(name) for row in group]
            values = [v for v in values if type(v) in {int, float} and math.isfinite(v)]
            metrics[name] = sum(values) / len(values) if values else None
        results.append({"project_id": project, "method": method, "condition": condition,
                        "split": split, "cases": len(group), "metrics": metrics})
    return results


def run_study(manifest_path, out):
    """Run all frozen arms, seal predictions, then read labels and score pairs."""
    from .evaluation import paired_bootstrap, score, validate_splits
    manifest_path, out = Path(manifest_path).absolute(), Path(out).absolute()
    # Reject symlink manifests and enormous control files before parsing.
    raw = read_frozen_blob(manifest_path.parent, manifest_path.name,
                           _sha(manifest_path.read_bytes()), 4 * 1024 * 1024)
    manifest = StudyManifest.model_validate_json(raw)
    split_check = validate_splits([{"project_id": c.project, "lineage_id": c.lineage, "split": c.split} for c in manifest.cases])
    out.mkdir(parents=True, exist_ok=False)
    (out / "manifest.json").write_bytes(raw)
    code_paths = sorted((ROOT / "sbom_recovery/investigation").glob("*.py"))
    code_paths += [ROOT / relative for relative in ("sbom_recovery/core/formats.py", "sbom_recovery/core/contracts.py",
        "sbom_recovery/reconciliation/contracts_v3.py", "sbom_recovery/reconciliation/merge_contracts_v3.py",
        "sbom_recovery/baselines/baselines.py")]
    source_code = {str(p.relative_to(ROOT)): _sha(p.read_bytes()) for p in code_paths}
    from importlib.metadata import PackageNotFoundError, version
    dependencies = {}
    for package in ("pydantic", "packageurl-python", "packaging", "jsonschema", "spdx-tools", "httpx"):
        try:
            dependencies[package] = version(package)
        except PackageNotFoundError:
            dependencies[package] = None
    freeze = {"schema_version": "investigation-study-freeze-v1", "manifest_sha256": _sha(raw),
              "source_code_sha256": _sha(json.dumps(source_code, sort_keys=True).encode()), "source_files": source_code,
              "dependencies": dependencies, "model": manifest.model, "seed": manifest.seed,
              "budget": manifest.budget.model_dump(), "comparator_commit": "521f3b8ee6e301e847f7cb113517ba46831e2b28",
              "split_validation": split_check, "case_ids": [c.case_id for c in manifest.cases],
              "methods": manifest.methods, "conditions": manifest.conditions,
              "label_access": "SCORER_ONLY_AFTER_ALL_PREDICTIONS_SEALED",
              "inference_boundary": "STAGED_SUBPROCESS_WITH_PYTHON_AUDIT_HOOK; NOT_AN_OS_SANDBOX"}
    _write(out / "freeze.json", freeze)
    records = []
    base = manifest_path.parent
    for case in manifest.cases:
        for condition in manifest.conditions:
            for method in manifest.methods:
                row = {"case_id": case.case_id, "project_id": case.project, "lineage_id": case.lineage,
                       "split": case.split, "method": method, "condition": condition, "status": "FAILED"}
                arm = out / "predictions" / case.case_id / condition / method
                try:
                    if any(_sha((ROOT / path).read_bytes()) != expected for path, expected in source_code.items()):
                        raise ValueError("Frozen inference source code changed during study")
                    with tempfile.TemporaryDirectory(prefix="eager-inference-") as temporary:
                        scratch = Path(temporary)
                        bundle = scratch / "public"
                        request, copied = _stage(case, base, bundle)
                        advisory_snapshot = None
                        if case.snapshot:
                            public_snapshot = read_frozen_blob(base, case.snapshot.path, case.snapshot.sha256, 32 * 1024 * 1024)
                            advisory_snapshot = json.loads(public_snapshot)
                            snapshot_path = bundle / "public-advisories.json"
                            if snapshot_path.exists():
                                raise ValueError("Reserved public advisory filename collides with an input")
                            snapshot_path.write_bytes(public_snapshot)
                            copied["public-advisories.json"] = case.snapshot.sha256
                        initial, precollection = [], None
                        effective_budget = manifest.budget.model_dump()
                        collection_started = time.monotonic()
                        if condition == "equal_information":
                            collector = EvidenceCatalog(request, bundle)
                            initial = [collector.acquire(d["source_id"]) for d in collector.descriptors()]
                            precollection = {"calls": len(initial), "bytes": sum(r.get("bytes_returned", 0) for r in initial),
                                "charged_to_arm": False, "interpretation": "Same pre-collected information across arms"}
                        elif method == "fixed_llm":
                            # Freeze a lexical source collection order. It gets
                            # the same catalog and budget as the adaptive arm,
                            # and its acquisition costs are charged before LLM
                            # interpretation begins.
                            collector = EvidenceCatalog(request, bundle)
                            for item in sorted(collector.descriptors(), key=lambda d: d["source_id"]):
                                if not effective_budget["max_tool_calls"] or not effective_budget["max_bytes"]:
                                    break
                                acquired = collector.acquire(item["source_id"], effective_budget["max_bytes"])
                                initial.append(acquired)
                                effective_budget["max_tool_calls"] -= 1
                                effective_budget["max_bytes"] -= acquired["bytes_returned"]
                            used_seconds = time.monotonic() - collection_started
                            effective_budget["max_seconds"] = max(0.001, manifest.budget.max_seconds - used_seconds)
                            precollection = {"calls": len(initial), "bytes": sum(r.get("bytes_returned", 0) for r in initial),
                                "seconds": used_seconds, "charged_to_arm": True,
                                "interpretation": "Fixed lexical acquisition charged against the same budget"}
                        config = {"request": "request.json", "out": str(arm), "method": method,
                                  "budget": effective_budget, "model": manifest.model,
                                  "model_base_url": manifest.model_base_url, "seed": manifest.seed,
                                  "initial_evidence": initial, "fixed_evidence": condition == "equal_information",
                                  "precollection": precollection,
                                  "original_budget": manifest.budget.model_dump(),
                                  "advisory_snapshot": advisory_snapshot,
                                  "advisory_ids": case.advisory_ids if case.advisory_ids is not None else manifest.advisory_ids,
                                  "audit": method != "sbom_unifier"}
                        config_path = scratch / "worker.json"
                        _write(config_path, config)
                        environment = {k: v for k, v in os.environ.items() if k in {"PATH", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT"}}
                        environment.update(PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
                        if method in {"agent", "fixed_llm"} and os.environ.get("NETMIND_API_KEY"):
                            environment["NETMIND_API_KEY"] = os.environ["NETMIND_API_KEY"]
                        # -I excludes the staged working directory from import
                        # search: repository-controlled json.py/sitecustomize.py
                        # files must never execute during dependency imports.
                        bootstrap = ("import runpy,sys;sys.path.insert(0," + repr(str(ROOT)) + ");"
                                     "sys.argv=['sbom_recovery.investigation.worker',sys.argv[1]];"
                                     "runpy.run_module('sbom_recovery.investigation.worker',run_name='__main__')")
                        process = subprocess.run([sys.executable, "-I", "-B", "-c", bootstrap, str(config_path)],
                            cwd=bundle, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=manifest.budget.max_seconds + 30, check=False)
                        if process.returncode:
                            # Tracebacks can contain raw input strings; retain a
                            # digest and bounded generic type, not arbitrary text.
                            raise ValueError("Inference worker exited " + str(process.returncode) + " (stderr sha256 " + _sha(process.stderr) + ")")
                        worker_result = json.loads(process.stdout)
                        row.update(worker_result)
                        row["public_inputs"] = copied
                        row["shared_acquisition"] = precollection
                        if row.get("status") == "PREDICTED":
                            row["seal_sha256"] = _sha((arm / "seal.json").read_bytes())
                            row["prediction_dir"] = str(arm.relative_to(out))
                except (ValueError, OSError, subprocess.SubprocessError) as exc:
                    row.update(status="FAILED", error=str(exc)[:500])
                records.append(row)
                _write(out / "prediction-index.json", {"schema_version": "investigation-prediction-index-v1", "records": records,
                                                       "oracle_bytes_read": False})
    # This checkpoint precedes the first permitted oracle open. A failed or
    # unsupported arm remains a row and cannot silently improve the denominator.
    _write(out / "inference-complete.json", {"all_predictions_terminal": True, "oracle_bytes_read": False,
                                             "records": len(records), "manifest_sha256": _sha(raw)})
    cases = {c.case_id: c for c in manifest.cases}
    oracles, snapshots = {}, {}
    for row in records:
        if row.get("status") != "PREDICTED":
            continue
        case = cases[row["case_id"]]
        try:
            prediction = _verify_seal(out / row["prediction_dir"], row["seal_sha256"])
            if case.case_id not in snapshots and case.snapshot:
                snapshots[case.case_id] = json.loads(read_frozen_blob(base, case.snapshot.path, case.snapshot.sha256, 32 * 1024 * 1024))
            if case.case_id in snapshots:
                from .security import assess
                prediction["security"] = assess(prediction, snapshots[case.case_id])
            if case.case_id not in oracles:
                oracles[case.case_id] = _read_oracle(base, case.oracle)
            scored = score(prediction, oracles[case.case_id])
            relative = Path("scores") / case.case_id / row["condition"] / (row["method"] + ".json")
            _write(out / relative, scored)
            row.update(status="SCORED", score=str(relative), metrics=_metrics(scored, prediction))
        except (ValueError, OSError, KeyError, TypeError) as exc:
            row.update(status="EVALUATION_FAILED", error=str(exc)[:500])
    project_rows = _project_summary(records)
    pairs = []
    for condition in manifest.conditions:
        for split in ("development", "test"):
            selected = [r for r in project_rows if r["condition"] == condition and r["split"] == split]
            for left, right in (("observed", "deterministic"), ("deterministic", "rule"), ("rule", "agent"),
                                ("metadata_only", "rule"), ("graph_only", "rule"), ("fixed_llm", "agent")):
                if left in manifest.methods and right in manifest.methods:
                    for metric in ("components_f1", "candidate_components_f1", "edges_f1", "candidate_edges_f1",
                                   "security_f1", "candidate_security_f1", "tool_calls"):
                        pairs.append({"condition": condition, "split": split, **paired_bootstrap(selected, metric,
                            left=left, right=right, samples=manifest.bootstrap_samples, seed=manifest.seed)})
    result = {"schema_version": "investigation-study-result-v1", "manifest_sha256": _sha(raw),
              "records": records, "per_project": project_rows, "paired_comparisons": pairs,
              "counts": dict(__import__("collections").Counter(r["status"] for r in records)),
              "oracle_access_protocol": "ALL_PREDICTIONS_SEALED_BEFORE_ANY_ORACLE_READ",
              "inference_boundary": freeze["inference_boundary"],
              "interpretation": "Controlled and real-world labels must be reported separately; agent superiority is not presumed"}
    _write(out / "report.json", result)
    return {"out": str(out), "cases": len(manifest.cases), "arms": len(records), "counts": result["counts"],
            "report": str(out / "report.json")}

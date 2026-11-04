"""Read-only cohort gates: chronological assignment, builds, labels, and native views."""
from datetime import datetime
from pathlib import Path

from research_core import load, digest
from .contracts import TargetContext
from .formats import NativeDocument, validate_native
from .scope import installed_view
from .targets import metadata_inventory


def validate_cohort(cohort_file, captures):
    cohort = load(cohort_file)
    records, failures = [], []
    names = [p["name"] for p in cohort["projects"]]
    repos = [p["repository"] for p in cohort["projects"]]
    if len(names) != 100 or len(set(names)) != 100 or len(set(repos)) != 100:
        failures.append("Expected 100 distinct project names and repositories")
    for partition, window in cohort["config"]["partitions"].items():
        if sum(p["partition"] == partition for p in cohort["projects"]) != window["count"]:
            failures.append("Partition size mismatch: " + partition)
    for project in cohort["projects"]:
        root = Path(captures) / project["name"]
        errors = []
        try:
            capture = load(root / "capture.json")
            if capture["status"] != "COMPLETE" or capture["pip_check"] != "PASSED":
                errors.append("Build validity gate failed")
            if capture["project"]["version"] != project["version"]:
                errors.append("Captured release differs from cohort")
            window = cohort["config"]["partitions"][project["partition"]]
            release = datetime.fromisoformat(project["released_at"].replace("Z", "+00:00"))
            if release > datetime.fromisoformat(window["end"].replace("Z", "+00:00")) or window["start"] and release < datetime.fromisoformat(window["start"].replace("Z", "+00:00")):
                errors.append("Release is outside chronological partition")
            context = TargetContext.model_validate(load(root / "context.json"))
            _, target_id = metadata_inventory(root / "runtime/target")
            if context.target_id != target_id:
                errors.append("Target metadata inventory changed")
            if context.python_full_version != cohort["config"]["target"]["python_full_version"]:
                errors.append("Interpreter differs from pinned target")
            proof = load(root / "oracle/installed_reference_provenance.json")
            if proof["pip_inspect_sha256"] != digest(root / "oracle/pip_inspect.json"):
                errors.append("Independent reference input digest mismatch")
            native = load(root / "runtime/syft.spdx.json")
            view, audit = installed_view(native, [f"pkg:pypi/{project['name']}@{project['version']}"])
            validity = validate_native(view)
            errors += [str(e) for e in validity["errors"]]
            records.append({"project": project["name"], "partition": project["partition"], "status": "PASSED" if not errors else "FAILED",
                            "errors": errors, "source": capture.get("source"), "observed_packages": len(NativeDocument(view).packages()),
                            "raw_input_sha256": digest(root / "runtime/syft.spdx.json"),
                            "reference_sha256": digest(root / "oracle/installed_reference.cdx.json")})
        except (ValueError, OSError, KeyError) as exc:
            records.append({"project": project["name"], "status": "FAILED", "errors": [str(exc)]})
    return {"status": "PASSED" if not failures and all(r["status"] == "PASSED" for r in records) else "FAILED",
            "cohort_sha256": digest(cohort_file), "projects": len(records), "failures": failures, "records": records,
            "oracle_inference_separation": "Oracle paths are absent from prediction worker mounts",
            "verification_scope": "Installed distribution declarations; not runtime imports or exploitability"}

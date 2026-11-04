"""Evaluation-only references from frozen pip inspect; never used for candidate acquisition."""
from pathlib import Path
from packaging.utils import canonicalize_name

from benchmark import gold_from_inspect, as_cyclonedx
from research_core import load, save, digest
from .storage import save, quarantine


def materialize(captures):
    results = []
    for report_path in sorted(Path(captures).glob("*/capture.json")):
        capture = load(report_path)
        if capture["status"] != "COMPLETE":
            continue
        oracle = report_path.parent / "oracle"
        inspection = load(oracle / "pip_inspect.json")
        original = load(oracle / "ground_truth.json")
        roots = [f"{r['metadata']['name']}=={r['metadata']['version']}" for r in inspection["installed"]]
        reference = gold_from_inspect(inspection, roots, load(oracle / "install_report.json"), capture["project"]["name"])
        reference["traversal_seeds"] = reference["roots"]
        reference["roots"] = original["roots"]
        reference["semantics"] = "All top-level installed distributions and their declared direct requirements; application roots retained separately from traversal seeds"
        for node in reference["nodes"]:
            node["requested_root"] = node["name"] in original["roots"]
        provenance = {"scope": "ALL_TOP_LEVEL_INSTALLED_DISTRIBUTIONS", "pip_inspect_sha256": digest(oracle / "pip_inspect.json"),
                      "installation_report_sha256": digest(oracle / "install_report.json"),
                      "builder_sha256": digest(Path(__file__).parents[1] / "benchmark.py"),
                      "reference_adapter_sha256": digest(__file__), "oracle_for_evaluation_only": True}
        fields = {}
        for row in inspection["installed"]:
            m = row["metadata"]
            name = canonicalize_name(m["name"])
            fields[name] = {"name": name, "version": m["version"], "purl": f"pkg:pypi/{name}@{m['version']}"}
            if m.get("license_expression"):
                fields[name]["licenseDeclared"] = m["license_expression"]
        for filename, value in (("installed_reference.json", reference), ("installed_reference.cdx.json", as_cyclonedx(reference)),
                                 ("installed_field_labels.json", {"fields": fields, "provenance": provenance}),
                                 ("installed_reference_provenance.json", provenance)):
            path = oracle / filename
            if path.exists():
                try:
                    existing = load(path)
                except (ValueError, UnicodeError):
                    quarantine(path)
                else:
                    if existing != value:
                        # Adapter implementation provenance may change while labels and input bindings
                        # are independently reverified. Preserve the original provenance bytes.
                        if filename == "installed_field_labels.json":
                            same_labels = existing.get("fields") == value.get("fields")
                            prior, current = existing.get("provenance", {}), value.get("provenance", {})
                        elif filename == "installed_reference_provenance.json":
                            same_labels = True
                            prior, current = existing, value
                        else:
                            same_labels, prior, current = False, {}, {}
                        binding_keys = ("scope", "pip_inspect_sha256", "installation_report_sha256", "builder_sha256")
                        if not same_labels or any(prior.get(k) != current.get(k) for k in binding_keys):
                            raise ValueError("Existing reference differs; never overwrite labels: " + str(path))
            if not path.exists():
                save(path, value)
        results.append({"project": capture["project"]["name"], "nodes": len(reference["nodes"]),
                        "edges": len(reference["edges"]), "provenance": load(oracle / "installed_reference_provenance.json"),
                        "reverified_adapter_sha256": digest(__file__),
                        "reference_sha256": digest(oracle / "installed_reference.cdx.json")})
    return {"status": "COMPLETE", "projects": len(results), "records": results,
            "scope": "Installed inventory and direct declarations, distinct from source-file inventory and runtime execution"}

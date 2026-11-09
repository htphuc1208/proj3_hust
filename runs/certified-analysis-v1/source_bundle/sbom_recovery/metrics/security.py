"""Frozen, retrospective OSV matching. Package paths are strictly Level 1 evidence."""
from collections import defaultdict, deque
from pathlib import Path
import httpx

from sbom_recovery.core.research_core import now, save, digest, load
from sbom_recovery.evidence.storage import save


def osv_snapshot(purls, destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    packages = sorted(set(purls))
    records = []
    with httpx.Client(timeout=60, follow_redirects=False) as client:
        for offset in range(0, len(packages), 500):
            batch = packages[offset:offset + 500]
            response = client.post("https://api.osv.dev/v1/querybatch", json={"queries": [{"package": {"purl": p}} for p in batch]})
            response.raise_for_status()
            body = response.json()
            save(destination / f"batch-{offset}.json", body)
            for purl, item in zip(batch, body["results"], strict=True):
                records.append({"purl": purl, "advisory_ids": sorted(v["id"] for v in item.get("vulns", []))})
    manifest = {"schema_version": "osv-snapshot-v1", "captured_at": now(), "assessment": "RETROSPECTIVE_CURRENT_KNOWLEDGE",
                "publication_at_deployment": "NOT_ESTABLISHED", "records": records,
                "response_sha256": {p.name: digest(p) for p in destination.glob("batch-*.json")}}
    save(destination / "snapshot.json", manifest)
    return manifest


def vulnerability_recovery(truth_edges, observed_edges, predicted_edges, roots, advisories):
    def reachable(edges):
        adjacent = defaultdict(set)
        for source, target in edges:
            adjacent[source].add(target)
        seen, queue = set(roots), deque(roots)
        while queue:
            for target in adjacent[queue.popleft()] - seen:
                seen.add(target)
                queue.append(target)
        return seen
    truth_edges = set(truth_edges)
    reference = reachable(truth_edges) - set(roots)
    population = {(p, a) for p, ids in advisories.items() if p in reference for a in ids}
    def found(edges):
        reached = reachable(set(edges) & truth_edges)
        return {(p, a) for p, a in population if p in reached}
    before, after = found(observed_edges), found(predicted_edges)
    return {"unit": "package_purl/advisory_id", "reference_population": len(population), "before": len(before),
            "after": len(after), "newly_recovered": sorted(after - before),
            "vrr_before": len(before) / len(population) if population else None,
            "vrr_after": len(after) / len(population) if population else None,
            "zero_denominator": "UNDEFINED", "evidence_level": 1, "openvex_status": "under_investigation",
            "path_scoring": "Only paths composed of independently confirmed direct edges receive credit; roots excluded",
            "triage_delta": None, "false_assurance_reduction": None,
            "interpretation": "Declared package-path visibility only; not exploitability"}


def score_campaign_security(run_root, captures, snapshot_file):
    from .metrics import graph_facts
    snapshot = load(snapshot_file)
    advisories = {r["purl"]: r["advisory_ids"] for r in snapshot["records"]}
    records = []
    for case_file in Path(run_root).rglob("records.json"):
        for row in load(case_file).get("records", []):
            arm = case_file.parent / row["method"]
            if not (arm / "seal.json").exists():
                continue
            seal = load(arm / "seal.json")
            if digest(arm / "prediction.spdx.json") != seal["prediction_sha256"]:
                raise ValueError("Prediction changed after sealing")
            capture = Path(captures) / row["project"]
            reference = load(capture / "oracle/installed_reference.cdx.json")
            gold = load(capture / "oracle/installed_reference.json")
            roots = {n["purl"] for n in gold["nodes"] if n["name"] == row["project"]}
            result = vulnerability_recovery(graph_facts(reference)[1], graph_facts(load(case_file.parent / "input.spdx.json"))[1],
                                            graph_facts(load(arm / "prediction.spdx.json"))[1], roots, advisories)
            save(arm / "security.json", result)
            records.append({"project": row["project"], "method": row["method"], "case": str(case_file.parent), **result})
    result = {"schema_version": "security-assessment-v1", "snapshot_sha256": digest(snapshot_file),
              "assessment": snapshot["assessment"], "records": records, "exploitability": "UNMEASURED"}
    save(Path(run_root) / "security_assessment.json", result)
    return {"assessed_arms": len(records), "snapshot_sha256": digest(snapshot_file), "exploitability": "UNMEASURED"}

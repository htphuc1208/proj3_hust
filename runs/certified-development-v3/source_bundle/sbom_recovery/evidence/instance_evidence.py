"""Expose physical candidates without collapsing a lock-coordinate group."""
from __future__ import annotations

from sbom_recovery.campaign.materialized_scope import match_files, read_identity


def describe_instances(document, catalog, target):
    bindings = match_files(document, catalog, target)
    entries = {e["evidence_id"]: e for e in catalog["entries"]}
    result = []
    for row in bindings["records"]:
        ids = ([row["evidence_id"]] if row["status"] == "FILE_BOUND_INSTANCE"
               else row["coordinate_group_evidence_ids"])
        candidates = []
        for evidence_id in ids:
            entry = entries[evidence_id]
            identity = read_identity(target, entry)
            candidates.append({"evidence_id": evidence_id, "metadata_path": entry["path"],
                               "sha256": entry["sha256"], "identity": identity})
        result.append({"scanner_ref": row["ref"], "status": row["status"],
                       "candidates": candidates, "candidate_count": len(candidates),
                       "selected_instance": row["evidence_id"] if row["status"] == "FILE_BOUND_INSTANCE" else None,
                       "identity_accuracy": "UNMEASURED", "dependency_edges": "NOT_INFERRED"})
    return {"schema_version": "instance-evidence-v1", "target_id": catalog["target_id"], "records": result,
            "interpretation": "Coordinate groups retain every physical candidate, including singleton groups; no instance-level edge claim"}

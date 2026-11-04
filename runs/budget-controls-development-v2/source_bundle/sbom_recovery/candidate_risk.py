"""Post-prediction advisory visibility; missing paths or lookups never imply safety."""
from collections import defaultdict, deque

from .formats import NativeDocument, package_purl, sha


def path_map(document, root_purls):
    native = NativeDocument(document)
    identities = {ref: package_purl(p, native.format) for ref, p in native.packages().items()}
    roots = [ref for ref,purl in identities.items() if purl in root_purls]
    adjacent = defaultdict(set)
    for parent, child in native.edges():
        if parent in identities and child in identities:
            adjacent[parent].add(child)
    paths = {r:[r] for r in roots}
    queue = deque(roots)
    while queue:
        parent = queue.popleft()
        for child in sorted(adjacent[parent]):
            if child not in paths:
                paths[child] = paths[parent] + [child]
                queue.append(child)
    by_purl = defaultdict(list)
    for ref,purl in identities.items():
        if purl:
            by_purl[purl].append(paths.get(ref))
    return {p: next((v for v in values if v is not None), None) for p,values in by_purl.items()}


def assess_risk(observed, candidate, roots, snapshot):
    before, after = path_map(observed, roots), path_map(candidate, roots)
    advisory = {r["purl"]:r["advisory_ids"] for r in snapshot["records"]}
    records = []
    for purl in sorted(before.keys() | after.keys()):
        for advisory_id in advisory.get(purl, []) or [None]:
            observed_path, candidate_path = before.get(purl), after.get(purl)
            level1_before = bool(observed_path and len(observed_path)>1)
            level1_after = bool(candidate_path and len(candidate_path)>1)
            status = ("OBSERVED_DECLARED_PATH" if level1_before else "CANDIDATE_DECLARED_PATH" if level1_after else "UNKNOWN")
            records.append({"purl":purl, "advisory_id":advisory_id,
                "advisory_lookup": "MATCHED" if advisory_id else "NO_MATCH_IN_SNAPSHOT" if purl in advisory else "UNKNOWN_NOT_QUERIED",
                "path_status": status, "observed_path_refs": observed_path,
                "candidate_path_refs": candidate_path, "evidence_level": 1 if level1_before or level1_after else 0,
                "changed_path_requires_review": level1_before != level1_after,
                "openvex_status":"under_investigation", "exploitability":"UNKNOWN",
                "artifact_inclusion":"UNVERIFIED"})
    return {"schema_version":"candidate-risk-v1", "snapshot_sha256":sha(snapshot),
            "snapshot_assessment":snapshot.get("assessment","UNRECORDED"), "records":records,
            "path_absence_status":"UNKNOWN", "vrr":None,"triage_delta":None,"false_assurance_reduction":None,
            "scope":"Package/advisory visibility and declared candidate paths; no product impact or exploitability assertion"}

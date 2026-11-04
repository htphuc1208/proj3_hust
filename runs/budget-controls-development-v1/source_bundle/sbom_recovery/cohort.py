"""Oracle-free, frozen chronological cohort acquisition with explicit shortfalls."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit

import httpx
from packaging.specifiers import SpecifierSet, InvalidSpecifier
from packaging.version import Version, InvalidVersion
from packaging.utils import canonicalize_name

from research_core import digest, load, now, save
from .formats import sha
from .storage import save

ROOT = Path(__file__).resolve().parents[1]
AWESOME = "https://raw.githubusercontent.com/vinta/awesome-python/master/README.md"
CONTROLS = ["requests", "requests-cache", "httpbin"]


def instant(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def github_repo(url):
    match = re.match(r"https?://(?:www\.)?github\.com/([^/#?]+)/([^/#?]+)", url or "", re.I)
    return (match.group(1) + "/" + match.group(2).removesuffix(".git")).lower() if match else None


def select_release(payload, interval, max_size):
    candidates = []
    for version, files in payload.get("releases", {}).items():
        try:
            parsed = Version(version)
        except InvalidVersion:
            continue
        if parsed.is_prerelease or parsed.is_devrelease:
            continue
        for artifact in files:
            timestamp = artifact.get("upload_time_iso_8601")
            if not timestamp or artifact.get("yanked") or artifact.get("packagetype") != "bdist_wheel":
                continue
            if not artifact.get("filename", "").endswith("-none-any.whl") or artifact.get("size", max_size + 1) > max_size:
                continue
            if instant(timestamp) > instant(interval["end"]) or interval["start"] and instant(timestamp) < instant(interval["start"]):
                continue
            try:
                if artifact.get("requires_python") and Version("3.11.16") not in SpecifierSet(artifact["requires_python"]):
                    continue
            except InvalidSpecifier:
                continue
            candidates.append((parsed, timestamp, artifact))
    if not candidates:
        return None
    version, timestamp, artifact = max(candidates, key=lambda x: (x[0], x[1], x[2]["filename"]))
    return {"version": str(version), "released_at": timestamp, "root_wheel": artifact}


def acquire(destination, protocol_file=None, workers=12, max_candidates=1200):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    config = load(protocol_file or ROOT / "configs/agent-recovery-v1.json")
    client = httpx.Client(timeout=30, follow_redirects=False)
    response = client.get(AWESOME)
    response.raise_for_status()
    (destination / "candidate-universe.md").write_text(response.text)
    urls = sorted(set(re.findall(r"https://github\.com/[\w.-]+/[\w.-]+", response.text)))
    repos = {github_repo(url): url for url in urls}
    candidates = sorted({canonicalize_name(url.rsplit("/", 1)[-1]) for url in urls} | set(CONTROLS),
                        key=lambda n: hashlib.sha256((str(config["selection_seed"]) + ":" + n).encode()).hexdigest())[:max_candidates]
    cache = destination / "registry"
    cache.mkdir()

    def fetch(name):
        try:
            result = client.get("https://pypi.org/pypi/" + name + "/json")
            if result.status_code != 200:
                return {"candidate": name, "status": "REGISTRY_HTTP_" + str(result.status_code)}
            payload = result.json()
            info = payload["info"]
            project_urls = list((info.get("project_urls") or {}).values()) + [info.get("home_page")]
            matches = sorted({github_repo(u) for u in project_urls if github_repo(u) in repos})
            if not matches:
                return {"candidate": name, "status": "NO_VERIFIED_REPOSITORY_LINK"}
            raw_path = cache / (name + ".json")
            raw_path.write_bytes(result.content)
            eligible = {partition: select_release(payload, window, config["max_root_wheel_bytes"])
                        for partition, window in config["partitions"].items()}
            return {"candidate": name, "name": canonicalize_name(info["name"]), "repository": matches[0],
                    "repository_url": "https://github.com/" + matches[0], "registry_file": str(raw_path.relative_to(destination)),
                    "registry_sha256": digest(raw_path), "eligible": eligible, "status": "ELIGIBLE" if any(eligible.values()) else "NO_ELIGIBLE_RELEASE"}
        except Exception as exc:
            return {"candidate": name, "status": "FETCH_FAILED", "error": type(exc).__name__}
    records = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for index, record in enumerate(pool.map(fetch, candidates), 1):
            records.append(record)
            if index % 100 == 0:
                print(json.dumps({"stage": "cohort_registry", "completed": index, "total": len(candidates)}), flush=True)
    client.close()
    selected, used_repos, used_names = [], set(), set()
    # Use controls only in development, then fixed hash order; never sort on measured recovery quality.
    ordered = sorted(records, key=lambda r: (r["candidate"] not in CONTROLS, candidates.index(r["candidate"])))
    for partition, window in config["partitions"].items():
        count = 0
        for row in ordered:
            release = row.get("eligible", {}).get(partition)
            if not release or row["repository"] in used_repos or row["name"] in used_names:
                continue
            if partition != "development" and row["candidate"] in CONTROLS:
                continue
            selected.append({k: v for k, v in row.items() if k != "eligible"} | release | {"partition": partition})
            used_repos.add(row["repository"])
            used_names.add(row["name"])
            count += 1
            if count == window["count"]:
                break
    counts = {part: sum(r["partition"] == part for r in selected) for part in config["partitions"]}
    manifest = {"schema_version": "cohort-v1", "status": "SELECTED" if all(counts[p] == w["count"] for p, w in config["partitions"].items()) else "SHORTFALL",
                "protocol_sha256": sha(config), "config": config, "selected_at": now(),
                "universe_url": AWESOME, "universe_sha256": digest(destination / "candidate-universe.md"),
                "selection": "verified repository link, pure Python wheel <=20MiB, fixed SHA256 order; no recovery metrics",
                "projects": selected, "counts": counts, "candidate_count": len(records),
                "scope_limitation": "Pure-Python-wheel roots; binary-heavy and unlinked projects excluded",
                "build_status": "NOT_RUN", "model_selection": "NOT_RUN"}
    save(destination / "cohort.json", manifest)
    save(destination / "selection_audit.json", {"records": records})
    return manifest


def replace_build_failures(cohort_file, capture_root, destination):
    """Replace only measured build failures, using the original oracle-free ranking."""
    original = load(cohort_file)
    audit = load(Path(cohort_file).parent / "selection_audit.json")["records"]
    revised = json.loads(json.dumps(original))
    for row in revised["projects"]:
        if not Path(row["registry_file"]).is_absolute():
            row["registry_file"] = str((Path(cohort_file).parent / row["registry_file"]).resolve())
    used_names = {r["name"] for r in original["projects"]}
    used_repos = {r["repository"] for r in original["projects"]}
    for attempted in Path(capture_root).glob("*/capture.json"):
        prior = load(attempted).get("project", {})
        if prior.get("name"):
            used_names.add(prior["name"])
        if prior.get("repository"):
            used_repos.add(prior["repository"])
    for historical in original.get("replacement_history", []):
        used_names.update(n for n in (historical.get("excluded"), historical.get("replacement")) if n)
    replacements = []
    for index, row in enumerate(original["projects"]):
        report = Path(capture_root) / row["name"] / "capture.json"
        if not report.exists() or load(report)["status"] != "FAILED":
            continue
        partition = row["partition"]
        alternative = next((r for r in audit if r.get("eligible", {}).get(partition)
                            and r.get("name") not in used_names and r.get("repository") not in used_repos
                            and r["candidate"] not in CONTROLS), None)
        if alternative is None:
            replacements.append({"excluded": row["name"], "status": "NO_ELIGIBLE_RESERVE", "partition": partition})
            continue
        release = alternative["eligible"][partition]
        new_row = {k: v for k, v in alternative.items() if k != "eligible"} | release | {"partition": partition}
        # Registry paths stay relative to the original frozen acquisition directory.
        new_row["registry_file"] = str((Path(cohort_file).parent / alternative["registry_file"]).resolve())
        revised["projects"][index] = new_row
        used_names.add(new_row["name"]); used_repos.add(new_row["repository"])
        replacements.append({"excluded": row["name"], "replacement": new_row["name"], "partition": partition,
                             "failure_manifest_sha256": digest(report), "reason": load(report).get("error")})
    revised.update(parent_cohort_sha256=digest(cohort_file), replacement_history=original.get("replacement_history", []) + replacements,
                   build_status="REQUIRES_CAPTURE", replacement_policy="original fixed ranking; build-failure status only, never prediction scores")
    # Preserve the frozen selection audit beside the revised manifest for additional rounds.
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(destination)
    save(destination, revised)
    audit_path = destination.parent / "selection_audit.json"
    if not audit_path.exists():
        save(audit_path, {"records": audit})
    return revised

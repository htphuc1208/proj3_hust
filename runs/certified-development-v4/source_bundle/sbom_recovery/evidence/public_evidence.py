"""Bounded public-artifact acquisition. Seeds come exclusively from observed SBOMs.

No oracle interface. Registry artifacts are evidence, never proof of target installation.
"""
from __future__ import annotations

import email.parser
import hashlib
import io
import json
import subprocess
import tarfile
import urllib.request
import zipfile
from datetime import datetime
from pathlib import Path

from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version
from sbom_recovery.core.research_core import components, digest, load, now, save
from sbom_recovery.campaign.container_runner import run_container


def fetch(url, limit=64 * 1024 * 1024):
    request = urllib.request.Request(url, headers={"User-Agent": "SBOM-research-validation/1"})
    with urllib.request.urlopen(request, timeout=45) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"Artifact exceeds byte budget: {url}")
    return data


def admitted_artifact(artifact, cutoff, python_version, wheel_tags):
    """Check availability, Python constraints and target tags; never use host tags."""
    uploaded = artifact.get("upload_time_iso_8601")
    if not uploaded or not cutoff:
        return False, "AVAILABILITY_TIME_UNKNOWN"
    if datetime.fromisoformat(uploaded.replace("Z", "+00:00")) > datetime.fromisoformat(cutoff.replace("Z", "+00:00")):
        return False, "FUTURE_ARTIFACT"
    if artifact.get("yanked"):
        return False, "YANKED_ARTIFACT"
    if artifact.get("requires_python") and Version(python_version) not in SpecifierSet(artifact["requires_python"]):
        return False, "PYTHON_INCOMPATIBLE"
    if artifact.get("packagetype") == "bdist_wheel":
        tags = parse_wheel_filename(artifact["filename"])[3]
        if not {str(t) for t in tags} & set(wheel_tags):
            return False, "WHEEL_TAG_INCOMPATIBLE"
    return True, "ADMITTED"


def seeds_from_observed(documents):
    seeds = set()
    for document in documents:
        for component in components(document):
            purl = component.get("purl", "")
            if purl.startswith("pkg:pypi/") and "@" in purl:
                name, version = purl[len("pkg:pypi/"):].split("?", 1)[0].rsplit("@", 1)
                seeds.add((canonicalize_name(name), version))
    return sorted(seeds)


def parse_core_metadata(raw, name, version, method):
    message = email.parser.BytesParser().parsebytes(raw)
    if canonicalize_name(message.get("Name", "")) != name or message.get("Version") != version:
        raise ValueError("Distribution metadata identity mismatch")
    metadata_version = message.get("Metadata-Version", "0")
    dynamic = message.get_all("Dynamic", [])
    is_static = method != "sdist-pkg-info" or (Version(metadata_version) >= Version("2.2") and
                not any("requires-dist" in d.lower() for d in dynamic))
    return {"name": name, "version": version, "metadata_version": metadata_version,
            "metadata_status": "COMPLETE" if is_static else "DYNAMIC_UNRESOLVED",
            "requires_dist": message.get_all("Requires-Dist", []) or [],
            "requires_python": message.get("Requires-Python", ""),
            "provides_extra": message.get_all("Provides-Extra", []) or [], "dynamic_fields": dynamic,
            "metadata_sha256": hashlib.sha256(raw).hexdigest(), "extraction_method": method}


def acquire(name, version, cache, context, allow_sdist=False):
    """Public wheel -> sdist PKG-INFO -> index Core Metadata -> independent backend.

    The registry response and downloaded archives are frozen with their own hashes.
    """
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    source = f"https://pypi.org/pypi/{name}/{version}/json"
    response_file = cache / f"{name}-{version}.index.json"
    if not response_file.exists():
        response_file.write_bytes(fetch(source))
    response = load(response_file)
    eligible, rejections = [], []
    for artifact in response.get("urls", []):
        ok, reason = admitted_artifact(artifact, context.get("cutoff"), context["python_full_version"], context["wheel_tags"])
        if ok:
            eligible.append(artifact)
        else:
            rejections.append({"filename": artifact["filename"], "reason": reason})
    wheels = sorted((a for a in eligible if a["packagetype"] == "bdist_wheel"), key=lambda a: a["filename"])
    sdists = sorted((a for a in eligible if a["packagetype"] == "sdist"), key=lambda a: a["filename"])
    record = {"name": name, "version": version, "metadata_status": "UNAVAILABLE", "requires_dist": [],
              "provenance": {"source_pypi_json_url": source, "fetched_at": now(),
                             "index_sha256": digest(response_file), "cutoff": context.get("cutoff"),
                             "cutoff_status": context.get("cutoff_status"), "rejections": rejections},
              "attempts": []}
    if not wheels and (not allow_sdist or not sdists):
        record["attempts"].append({"method": "wheel", "status": "NO_COMPATIBLE_PUBLIC_WHEEL"})
        return record
    artifact = wheels[0] if wheels else sdists[0]
    archive = cache / artifact["filename"]
    if not archive.exists():
        archive.write_bytes(fetch(artifact["url"]))
    if digest(archive) != artifact["digests"]["sha256"]:
        raise ValueError("Public distribution digest mismatch")
    record["provenance"].update(artifact_url=artifact["url"], artifact_filename=artifact["filename"],
                                 artifact_sha256=digest(archive), uploaded_at=artifact["upload_time_iso_8601"])
    record["distribution_type"] = artifact["packagetype"]
    if wheels:
        with zipfile.ZipFile(archive) as z:
            names = [p for p in z.namelist() if p.endswith(".dist-info/METADATA") and len(Path(p).parts) == 2]
            if len(names) != 1:
                raise ValueError("Ambiguous wheel METADATA")
            parsed = parse_core_metadata(z.read(names[0]), name, version, "public-wheel")
        record.update(parsed)
        record["attempts"].append({"method": "public-wheel", "status": "COMPLETE"})
        return record
    with tarfile.open(archive) as tar:
        members = [m for m in tar.getmembers() if m.isfile() and m.name.endswith("/PKG-INFO")
                   and len(Path(m.name).parts) == 2 and m.size < 4 * 1024 * 1024]
        if len(members) == 1:
            parsed = parse_core_metadata(tar.extractfile(members[0]).read(), name, version, "sdist-pkg-info")
            record.update(parsed)
            record["attempts"].append({"method": "sdist-pkg-info", "status": parsed["metadata_status"]})
            if parsed["metadata_status"] == "COMPLETE":
                return record
    # PEP 658/714 availability is advertised by the index; do not invent a metadata URL.
    simple_file = cache / f"{name}.simple.json"
    try:
        request = urllib.request.Request(f"https://pypi.org/simple/{name}/",
            headers={"Accept": "application/vnd.pypi.simple.v1+json", "User-Agent": "SBOM-research-validation/1"})
        if not simple_file.exists():
            with urllib.request.urlopen(request, timeout=45) as response:
                simple_file.write_bytes(response.read(16 * 1024 * 1024))
        entry = next((f for f in load(simple_file).get("files", []) if f["filename"] == artifact["filename"]), {})
        metadata_digest = entry.get("core-metadata", entry.get("dist-info-metadata"))
        if metadata_digest:
            raw = fetch(entry["url"] + ".metadata")
            if isinstance(metadata_digest, dict) and hashlib.sha256(raw).hexdigest() != metadata_digest.get("sha256"):
                raise ValueError("Index metadata digest mismatch")
            parsed = parse_core_metadata(raw, name, version, "sdist-pkg-info")
            record.update(parsed)
            record["attempts"].append({"method": "index-core-metadata", "status": parsed["metadata_status"]})
            if parsed["metadata_status"] == "COMPLETE":
                return record
        else:
            record["attempts"].append({"method": "index-core-metadata", "status": "NOT_ADVERTISED"})
    except Exception as exc:
        record["attempts"].append({"method": "index-core-metadata", "status": "FAILED", "error": str(exc)})
    built = cache / f"build-{name}-{version}"
    built.mkdir(exist_ok=True)
    command = ["docker", "run", "--rm", "--network", "none", "--cap-drop=ALL", "--security-opt", "no-new-privileges",
               "--memory=2g", "--cpus=2", "--pids-limit=128", "--user", "1000:1000",
               "-v", f"{archive.resolve()}:/source/{archive.name}:ro", "-v", f"{built.resolve()}:/out:rw",
               "--entrypoint", "python", context["image"], "-m", "pip", "wheel", "--no-deps", "--no-build-isolation",
               "--no-index", "--wheel-dir", "/out", f"/source/{archive.name}"]
    started = now()
    try:
        result = run_container(command, timeout=600)
        (built / "build.log").write_text(result.stdout + result.stderr)
        build_record = {"method": "independent-backend", "command": command, "started_at": started,
                        "completed_at": now(), "image": context["image"], "exit_code": result.returncode,
                        "dynamic_build_dependencies": "No network or build-dependency installation permitted; preinstalled tools only",
                        "build_environment": context.get("build_environment", {}), "log_sha256": digest(built / "build.log")}
        record["attempts"].append(build_record)
        wheel_files = sorted(built.glob("*.whl"))
        if result.returncode or len(wheel_files) != 1:
            raise RuntimeError("Independent backend failed; see build.log")
        with zipfile.ZipFile(wheel_files[0]) as z:
            path = next(n for n in z.namelist() if n.endswith(".dist-info/METADATA"))
            parsed = parse_core_metadata(z.read(path), name, version, "independent-sdist-build")
        record.update(parsed)
        record["provenance"].update(independent_wheel_sha256=digest(wheel_files[0]), build_context=context)
        build_record["status"] = "COMPLETE"
    except Exception as exc:
        record["metadata_status"] = "DYNAMIC_UNRESOLVED"
        record["attempts"].append({"method": "independent-backend", "status": "BLOCKED", "error": str(exc)})
    return record


def expand_snapshot(base, destination, documents, context, allow_sdist=False, offline=False):
    """Exact observed-parent evidence acquisition, not full registry enumeration."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    old_manifest = load(Path(base) / "evidence_manifest.json")
    manifest = {"schema_version": "evidence-snapshot-v4", "frozen_at_utc": now(),
                "completeness": "PARTIAL_CANDIDATE_UNIVERSE", "selection_policy": "All exact observed distribution identities; sorted, no oracle seeds",
                "legacy_snapshot_sha256": digest(Path(base) / "evidence_manifest.json"), "artifacts": [], "query_audit": []}
    records = {(a["name"], a["version"]): load(Path(base) / a["metadata_file"]) for a in old_manifest["artifacts"]}
    seeds = seeds_from_observed(documents)
    manifest["seeds"] = seeds
    for name, version in seeds:
        old = records.get((name, version))
        incomplete = old is None or old.get("metadata_status") in ("UNAVAILABLE", "DYNAMIC_UNRESOLVED") or old.get("provenance", {}).get("verification_status") == "RELEASE_METADATA_FALLBACK"
        if not incomplete:
            continue
        if offline:
            raise RuntimeError("Offline snapshot expansion is unavailable; replay the previously frozen output snapshot")
        try:
            record = acquire(name, version, destination.parent / "public_cache", context, allow_sdist)
            records[(name, version)] = record
            manifest["query_audit"].append({"name": name, "version": version, "status": record["metadata_status"]})
        except Exception as exc:
            manifest["query_audit"].append({"name": name, "version": version, "status": "BLOCKED", "error": str(exc)})
    for (name, version), record in sorted(records.items()):
        filename = f"{name}-{version}.json"
        save(destination / filename, record)
        manifest["artifacts"].append({"name": name, "version": version, "metadata_file": filename,
                                      "sha256": digest(destination / filename)})
    save(destination / "evidence_manifest.json", manifest)
    return manifest

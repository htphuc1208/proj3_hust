"""Trusted preparation/reader. Policies receive catalog metadata, never a target path."""
from datetime import datetime
from pathlib import Path
import hashlib
import re

from packaging.utils import canonicalize_name

from .formats import sha
from .gold_contracts import contained
from .targets import metadata_inventory


def timestamp(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Explicit UTC offset required")
    return result


def validate_catalog(catalog, context):
    if set(catalog) != {"schema_version", "target_id", "sources", "hint_scope", "sha256"}:
        raise ValueError("Unexpected catalog fields")
    unsigned = {k: v for k, v in catalog.items() if k != "sha256"}
    if catalog.get("schema_version") != "budget-source-catalog-v1" or sha(unsigned) != catalog.get("sha256"):
        raise ValueError("Catalog digest mismatch")
    if catalog["target_id"] != context.target_id:
        raise ValueError("Catalog belongs to another target")
    seen = set()
    for row in catalog["sources"]:
        if set(row) != {"source_id", "path", "kind", "name_hint", "sha256", "bytes", "available_at"}:
            raise ValueError("Unexpected source fields; raw metadata/labels cannot enter the initial catalog")
        if (row["source_id"] in seen or row["kind"] != "installed_metadata"
                or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                or row["source_id"] != sha([catalog["target_id"], row["path"], row["sha256"]])
                or type(row["bytes"]) is not int or row["bytes"] < 0):
            raise ValueError("Invalid catalog source")
        seen.add(row["source_id"])
        if any(part.lower() in {"oracle", "gold", "annotations", "ground_truth"} for part in Path(row["path"]).parts):
            raise ValueError("Oracle/annotation sources denied")
        # Validate containment syntax without inspecting source bytes.
        contained(Path("/catalog"), row["path"])
        timestamp(row["available_at"])
    return catalog


def prepare_catalog(target, context, available_at):
    """Collector-only hashing; no metadata identity/requirement parser or reference read."""
    target = Path(target).resolve(strict=True)
    paths, binding = metadata_inventory(target)
    if binding != context.target_id:
        raise ValueError("Target snapshot differs from context")
    timestamp(available_at)
    sources = []
    for path in paths:
        if path.parent.parent.name not in {"site-packages", "dist-packages"}:
            continue
        relative = path.relative_to(target).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        # Filename hints are observable catalog information, never truth labels.
        name_hint = canonicalize_name(path.parent.name.removesuffix(".dist-info").rsplit("-", 1)[0])
        sources.append({"source_id": sha([binding, relative, digest]), "path": relative,
                        "kind": "installed_metadata", "name_hint": name_hint,
                        "sha256": digest, "bytes": path.stat().st_size, "available_at": available_at})
    catalog = {"schema_version": "budget-source-catalog-v1", "target_id": binding, "sources": sources,
               "hint_scope": "Observed filename hints only; no parsed identities, requirements or reference membership"}
    catalog["sha256"] = sha(catalog)
    return validate_catalog(catalog, context)


class TrustedReader:
    """Lives in the controller. Workers receive only its bounded RPC responses."""
    def __init__(self, target, catalog, context):
        self.target = Path(target).resolve(strict=True)
        validate_catalog(catalog, context)
        self.sources = {row["source_id"]: row for row in catalog["sources"]}
        self.context = context
        self.attempts = []

    def read(self, source_id, limit):
        self.attempts.append(source_id)
        if source_id not in self.sources or type(limit) is not int or limit < 0:
            raise ValueError("Unknown source or invalid byte allowance")
        source = self.sources[source_id]
        if timestamp(source["available_at"]) > timestamp(self.context.evidence_cutoff):
            raise ValueError("Evidence after cutoff")
        if source["bytes"] > limit:
            raise ValueError("Source exceeds byte allowance")
        path = contained(self.target, source["path"])
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit or len(raw) != source["bytes"] or hashlib.sha256(raw).hexdigest() != source["sha256"]:
            raise ValueError("Source bytes changed or exceeded allowance")
        return raw

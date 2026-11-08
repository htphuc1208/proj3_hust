#!/usr/bin/env python3
"""Bounded public B6 acquisition seeded exclusively by observed SBOM roots."""
import argparse
from pathlib import Path
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from depsdev_baseline import dependencies_url
from research_core import RunBundle, digest, load, now
from resolver import normalize_purl


def capture(out, observations):
    bundle = RunBundle(out, Path(out).name, purpose="Three-root deps.dev public snapshot; no oracle access",
                       data_kind="CONTEMPORARY_REMOTE_EVIDENCE", maximum_http_requests=3)
    bundle.data["protocol"] = "m2.4-open-world-v1"
    records = []
    inputs = sorted(Path(observations).glob("*/syft/normalized.cdx.json"))
    if len(inputs) != 3:
        bundle.finish("FAILED", reason="Expected the declared three-pilot observed cohort")
        raise ValueError("Expected exactly three observed SBOM inputs")
    for path in inputs:
        document = load(path)
        root = normalize_purl(document.get("metadata", {}).get("component", {}).get("purl", ""))
        url = dependencies_url(root)
        project = path.parent.parent.name
        record = {"project": project, "root_purl": root, "url": url, "requested_at": now(),
                  "seed_source": str(path.relative_to(ROOT)), "seed_sha256": digest(path)}
        started = time.perf_counter()
        try:
            request = Request(url, headers={"User-Agent": "sbom-security-poc-research/2.4", "Accept": "application/json"})
            with urlopen(request, timeout=20) as response:
                content = response.read(8_000_001)
                if len(content) > 8_000_000:
                    raise ValueError("Response exceeds acquisition budget")
                record["http_status"] = response.status
                record["response_headers"] = {k: response.headers[k] for k in ("Date", "ETag", "Last-Modified")
                                                if response.headers.get(k)}
            import json
            json.loads(content)
            relative = f"responses/{project}.json"
            target = Path(out) / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            bundle.data["artifacts"][relative] = {"sha256": digest(target), "written_at": now(), "source": url}
            record.update(status="AVAILABLE", response_file=relative, response_sha256=digest(target))
        except (HTTPError, URLError, OSError, ValueError) as exc:
            record.update(status="UNAVAILABLE", error=str(exc))
        record.update(completed_at=now(), duration_seconds=time.perf_counter() - started)
        records.append(record)
        bundle.artifact("acquisition.json", {"schema_version": "depsdev-acquisition-v1", "queries": records,
            "requests": len(records), "maximum_http_requests": 3, "selection": "Observed exact metadata root only; no reference labels"})
    failed = sum(record["status"] != "AVAILABLE" for record in records)
    bundle.finish("COMPLETE" if not failed else "PARTIAL", failed_queries=failed)
    print({"queries": len(records), "available": len(records) - failed, "out": str(out)})
    return 1 if failed else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--observations", type=Path, default=ROOT / "runs/m23-validation-v2")
    args = parser.parse_args()
    sys.exit(capture(args.out, args.observations))

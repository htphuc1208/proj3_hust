"""Read-only, verified controlled-pilot results, separate from target recovery."""
from pathlib import Path
import re

from sbom_recovery.reachability_pilot import digest, read, verify


RUNS = Path(__file__).resolve().parents[1] / "runs"


def latest():
    roots = [p for p in RUNS.glob("level23-pilot-v*")
             if re.fullmatch(r"level23-pilot-v[0-9]+", p.name) and p.is_dir() and not p.is_symlink()
             and (p / "summary.json").is_file() and (p / "seal.json").is_file()]
    if not roots:
        return {"status": "UNAVAILABLE", "reason": "Chưa có pilot Level 2–3 đã hoàn tất và niêm phong."}
    root = max(roots, key=lambda p: int(p.name.rsplit("v", 1)[1]))
    # Invalid new results must not silently fall back to an older successful run.
    verification = verify(root)
    summary = read(root / "summary.json")
    for case in summary["cases"]:
        raw = read(root / case["raw_result"])
        case["audit_events"] = raw.get("audit_events", [])
        case["input_sha256"] = raw.get("input_sha256")
        case["environment"] = raw.get("environment")
        case["libyaml_active"] = raw.get("libyaml_active")
    return {"status": "VERIFIED", "run": root.name, "verification": verification,
            "summary_sha256": digest(root / "summary.json"), "summary": summary,
            "scope": "Pilot ứng dụng kiểm soát với upstream PyYAML; độc lập với target SBOM đang chọn."
                     " Kết quả không chứng minh Agent vượt baseline hoặc an toàn cho mọi đầu vào."}

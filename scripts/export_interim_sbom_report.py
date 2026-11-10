#!/usr/bin/env python3
"""Export a paired, sealed checkpoint without changing the running benchmark.

The scheduled worker requires no gateway credential and performs no inference.
An interim sample is censored by completion time, so its estimates are descriptive.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from research_core import digest, load, now
from sbom_recovery.campaign import flat_scores
from sbom_recovery.formats import sha
from sbom_recovery.freeze import freeze
from sbom_recovery.metrics import paired_bootstrap, holm
from sbom_recovery.reporting import aggregate, read_records, report
from sbom_recovery.security import score_campaign_security
from sbom_recovery.storage import save, save_bytes

METHODS = ("observed", "single_scanner", "sbom_unifier", "unifier_rules",
           "deterministic", "single_agent", "multi_agent")
BINDINGS = ("input_sha256", "context_sha256", "evidence_input_sha256",
            "implementation_sha256", "input_preparation_sha256", "input_origin",
            "single_scanner", "budget", "condition", "family",
            "rate", "mask_seed", "repetition")
CHILDREN = []


def instant(value):
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("A checkpoint cutoff needs an explicit timezone")
    return stamp.astimezone(timezone.utc)


def csv_file(path, rows):
    import csv
    import io
    if not rows:
        return
    text = io.StringIO()
    writer = csv.DictWriter(text, fieldnames=list(rows[0]))
    writer.writeheader(); writer.writerows(rows)
    save_bytes(path, text.getvalue().encode())


def paired_case(rows):
    """An error outcome is eligible; an unfinished or mismatched comparison is not."""
    if len(rows) != len(METHODS) or Counter(r["method"] for r in rows) != Counter(METHODS):
        raise ValueError("All seven distinct method outcomes are required")
    first = rows[0]
    bindings = BINDINGS + (("calibration_sha256",) if any(
        "calibration_sha256" in r for r in rows) else ())
    for row in rows:
        if any(k not in row or row[k] != first.get(k) for k in bindings):
            raise ValueError("Methods have different permitted input/context/evidence bindings")
        if row.get("partition") != "test" or row["family"] != "raw":
            raise ValueError("This checkpoint exports the held-out raw track only")
        if not row.get("status") or row["status"] in {"RUNNING", "PENDING"}:
            raise ValueError("An unfinished method cannot be an evaluated outcome")


def copy_snapshot_file(source, destination):
    """Atomic upstream writers make hard links stable across later replacements."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(source, destination)
    except OSError:
        shutil.copyfile(source, destination)
    return digest(destination)


def take_snapshot(study, destination, cutoff):
    study, destination = Path(study), Path(destination)
    stage = study / "test/raw"
    settings = load(stage / "campaign.json")["settings"]
    selection = load(study / "model-selection.json")
    if selection.get("status") != "FROZEN" or selection.get("test_labels_used") is not False:
        raise ValueError("The model choice must be frozen without test labels")
    if set(settings["methods"]) != set(METHODS):
        raise ValueError("Unexpected primary method panel")
    destination.mkdir(parents=True, exist_ok=False)
    hashes, omitted, included = {}, [], []
    records_seen = 0
    for file in sorted(stage.rglob("records.json")):
        rows = load(file).get("records", [])
        records_seen += 1
        relative = file.parent.relative_to(stage)
        try:
            paired_case(rows)
        except ValueError as exc:
            omitted.append({"case": str(relative), "reason": str(exc)})
            continue
        seals = {r["method"]: load(file.parent / r["method"] / "seal.json") for r in rows}
        if any(instant(s["sealed_at"]) > cutoff for s in seals.values()):
            omitted.append({"case": str(relative), "reason": "SEALED_AFTER_CUTOFF"})
            continue
        missing = [r["method"] for r in rows if not (file.parent / r["method"] / "evaluation.json").exists() or "metrics" not in r]
        if missing:
            omitted.append({"case": str(relative), "reason": "SCORING_UNAVAILABLE", "methods": missing})
            continue
        observation = load(file.parent / "input.spdx.json")
        evidence = load(file.parent / "evidence_binding.json")
        for row in rows:
            arm = file.parent / row["method"]
            seal = seals[row["method"]]
            if any(row.get(k) != v for k, v in seal["spec"].items()):
                raise ValueError("The record differs from its sealed specification: " + str(arm))
            if seal.get("oracle_exposed_to_prediction_worker") is not False:
                raise ValueError("Missing worker-oracle isolation declaration")
            if sha(observation) != row["input_sha256"] or sha(evidence) != row["evidence_input_sha256"]:
                raise ValueError("A sealed case input or evidence catalog changed")
            if digest(arm / "prediction.spdx.json") != seal["prediction_sha256"]:
                raise ValueError("A prediction changed after sealing")
            if flat_scores(load(arm / "evaluation.json")) != row["metrics"]:
                raise ValueError("Recorded F1 differs from the saved evaluation")
        files = [file]
        files += [file.parent / n for n in ("input.spdx.json", "evidence_binding.json", "input_preparation.json", "scope_audit.json") if (file.parent / n).exists()]
        for row in rows:
            files += [file.parent / row["method"] / n for n in (
                "prediction.spdx.json", "seal.json", "evaluation.json", "record.json",
                "validation.json", "coverage.json", "details.json",
            ) if (file.parent / row["method"] / n).exists()]
        for source in files:
            target = destination / source.relative_to(stage)
            hashes[str(source)] = {"snapshot": str(target), "sha256": copy_snapshot_file(source, target)}
        for row in rows:
            arm = destination / relative / row["method"]
            if digest(arm / "prediction.spdx.json") != seals[row["method"]]["prediction_sha256"]:
                raise ValueError("A prediction changed while taking the snapshot")
        included.append({"case": str(relative), "project": rows[0]["project"],
            "condition": rows[0]["condition"], "repetition": rows[0]["repetition"],
            "last_prediction_at": max(s["sealed_at"] for s in seals.values())})
    result = {"schema_version": "paired-interim-snapshot-v1", "cutoff": cutoff.isoformat(),
        "included_cases": included, "omitted_cases": omitted, "case_records_seen": records_seen,
        "snapshot_sha256": hashes, "source_campaign_sha256": digest(stage / "campaign.json"),
        "selection_sha256": digest(study / "model-selection.json"),
        "measurement": "Saved independent-reference evaluations; scores checked against records",
        "failures": "Terminal failures retained; unscored outcomes disclosed separately",
        "censoring": "Completion-time censored; pending cases are not successful or negative outcomes"}
    return result, settings


def completed_project_rows(rows, repetitions):
    cases = defaultdict(set)
    for row in rows:
        cases[(row["project"], row["condition"])].add(row["repetition"])
    eligible = {key for key, values in cases.items() if values == set(range(repetitions))}
    return [r for r in rows if (r["project"], r["condition"]) in eligible]


def export(study, out, cutoff):
    study, out = Path(study).resolve(), Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    snapshot, settings = take_snapshot(study, out / "snapshot", cutoff)
    save(out / "snapshot-manifest.json", snapshot)
    plan = load(study / "plan.json")
    advisory = Path(plan["snapshot"])
    if not advisory.is_absolute():
        advisory = study.parent.parent / advisory
    if digest(advisory) != plan["snapshot_sha256"]:
        raise ValueError("The frozen OSV snapshot changed")
    # Assessment is written only into this independent reporting snapshot.
    security = score_campaign_security(out / "snapshot", settings["captures"], advisory)
    rows, provenance = read_records(out / "snapshot")
    report(out / "snapshot", out / "report")
    summary = aggregate(rows)
    comparisons = []
    for condition in sorted({r["condition"] for r in rows}):
        subset = [r for r in rows if r["condition"] == condition]
        for method in ("single_agent", "multi_agent"):
            for baseline in ("sbom_unifier", "unifier_rules", "deterministic"):
                for metric in ("new_metadata_f1", "new_direct_edge_f1", "whole_metadata_f1", "whole_direct_edge_f1"):
                    comparisons.append({"condition": condition, **paired_bootstrap(subset, method, baseline, metric)})
    save(out / "report/paired-comparisons.json", {"role": "EXPLORATORY_INTERIM_ONLY",
        "warning": "Nominal project intervals; no sequential testing guarantee; do not tune on held-out results",
        "comparisons": holm(comparisons)})
    full = aggregate(completed_project_rows(rows, settings["repetitions"]))
    save(out / "report/completed-project-panel.json", {"required_repetitions_per_condition": settings["repetitions"],
        "groups": full, "interpretation": "Empty groups mean no complete project/condition panel yet"})
    coverage_groups = defaultdict(list)
    for file in (out / "snapshot").rglob("records.json"):
        for row in load(file)["records"]:
            path = file.parent / row["method"] / "coverage.json"
            if path.exists():
                for scope, value in load(path)["scopes"].items():
                    coverage_groups[(row["condition"], row["method"], scope, row["project"])].append(
                        100 * value["full"] / value["evaluated_fields"])
    coverage = defaultdict(list)
    for (condition, method, scope, project), values in coverage_groups.items():
        coverage[(condition, method, scope)].append(sum(values) / len(values))
    csv_file(out / "report/field-coverage.csv", [{"condition": k[0], "method": k[1], "scope": k[2],
        "projects": len(values), "fully_covered_pct": sum(values) / len(values),
        "interpretation": "Original analyzer field presence, not correctness"} for k, values in sorted(coverage.items())])
    csv_file(out / "report/completed-project-metrics.csv", full)
    count = len(snapshot["included_cases"])
    population = len({r["project"] for r in rows})
    by_condition = Counter(r["condition"] for r in snapshot["included_cases"])
    errors = sum(r.get("status") != "COMPLETE" for r in rows)
    table = "\n".join(f"| {r['condition']} | {r['method']} | {r['projects']} | {r['cases']} | {fmt(r['whole_node_f1'])} | {fmt(r['whole_direct_edge_f1'])} ({r['whole_direct_edge_f1_n_projects']}) | {fmt(r['whole_metadata_f1'])} | {r['incomplete']} | {r['validation_failed']} |" for r in summary)
    failure = {"status_counts": dict(Counter(r.get("status") for r in rows)),
        "agent_status_counts": {m: dict(Counter(r["status"] for r in rows if r["method"] == m)) for m in ("single_agent", "multi_agent")},
        "causal_attribution": "A–E only where recorded; otherwise UNRESOLVED"}
    save(out / "report/failures.json", failure)
    text = f'''# Báo cáo tạm thời: AI Agent và sbom-unifier

Mốc chốt prediction: **{cutoff.isoformat()}**. Xuất lúc {now()}. **INTERIM — chưa hoàn tất benchmark**.

## Context & Problem Formulation

Đánh giá khôi phục inventory, metadata và dependency trực tiếp của các bản phát hành PyPI trong môi trường đã cố định. Hiện có **{count}/360 ca** đủ cả bảy phương pháp, gồm **{population}/60 dự án**; theo điều kiện: {dict(by_condition)}. Số lượt lặp được trung bình trong từng dự án. Các bản sửa vẫn là khai báo ứng viên; không suy ra đã cài đặt trong sản phẩm triển khai hoặc có thể khai thác.

## Theoretical Background & Sourcing

[Moriwaki et al., 2026, sbom-unifier, ICSME Tool Demonstrations](https://arxiv.org/abs/2608.30708) cung cấp phép đo 39 trường; `field-coverage.csv` giữ phép đo độ hiện diện này riêng với độ đúng. Ngữ nghĩa native theo [SPDX 2.3](https://spdx.github.io/spdx-spec/v2.3/); dependency được điều kiện hóa theo môi trường và [PyPA dependency specifiers](https://packaging.python.org/en/latest/specifications/dependency-specifiers/).

## Hypothesis & Experimental Design

Mỗi ca so sánh đủ cùng bảy phương pháp trên cùng input/context/evidence catalog, có kiểm tra hash và prediction seal. Giữ cả lỗi mô hình/timeout; không chỉ chọn lượt thành công. Fixed và active tách riêng. Ca chưa kết thúc hoặc chưa chấm được được ghi riêng trong snapshot manifest. Mô hình và chính sách abstention đã khóa trước test; báo cáo không sửa chúng.

**Mẫu tạm thời bị lệch theo thời gian hoàn tất**: dự án lớn/chậm và các lượt lặp sau có thể còn thiếu. Các khoảng tin cậy theo dự án là mô tả thăm dò, không có bảo đảm kiểm định tuần tự. Không dùng bản tạm để tuyên bố thắng baseline hoặc điều chỉnh mô hình. `completed-project-panel.json` cung cấp riêng các dự án/điều kiện đủ cả ba lượt lặp; có thể hiện chưa có dự án đủ.

## Empirical Evidence & Downstream Metrics

Các điểm dưới đây là F1 toàn inventory, trung bình theo dự án; số n sau điểm cạnh là số dự án có mẫu số xác định. CSV giữ precision, recall, F1 cho cả phần mới khôi phục và toàn bộ dữ liệu, mẫu số, token, thời gian và trạng thái.

| Điều kiện | Phương pháp | Dự án | Ca | Node F1 | Edge F1 (n) | Metadata F1 | Lượt lỗi/giới hạn | SPDX không hợp lệ |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
{table}

Đã lưu **{errors} lượt chưa đạt trạng thái COMPLETE** trong bảng trên. Lượt thực thi COMPLETE vẫn có thể tạo SPDX không hợp lệ; hai chỉ số được tách riêng. F1 của dữ liệu trích xuất vẫn được giữ cho baseline có lỗi cấu trúc. [metrics.csv](metrics.csv), [khoảng tin cậy ghép cặp](paired-comparisons.json), [lỗi thực thi](failures.json), [39-field coverage](field-coverage.csv).

Đã đánh giá {security['assessed_arms']} lượt bằng snapshot OSV hồi cứu đã khóa. VRR chỉ đo đường phụ thuộc Level 1 qua các cạnh được ground truth xác nhận; advisory ID không đồng nghĩa CVE riêng biệt. Không có đường đi là UNKNOWN; không kết luận SAFE. VEX triage delta, false-assurance reduction, call-graph reachability và exploitability vẫn UNMEASURED.

## Failure Taxonomy & Threats to Validity

Các lỗi node/cạnh/metadata lưu taxonomy A–E hoặc UNRESOLVED; không tự đoán nguyên nhân. Timeout, đầu ra bị cắt, lượt chưa chạy và lỗi SPDX đều được ghi nhận. Construct validity: độ đầy đủ trường, độ đúng dependency và exploitability là các đại lượng khác nhau. Internal validity: mẫu hoàn tất sớm và số lượt lặp chưa đồng đều; reference chỉ dùng cho đánh giá sau seal. External validity: một hệ sinh thái/môi trường, bộ dự án có chọn lọc và dependency dùng chung. Cải thiện nhờ artifact evidence chưa chứng minh đóng góp riêng của LLM.

## Actionable Next Steps

Benchmark chính tiếp tục theo ma trận đã khóa. Sau đủ 360 ca raw, đối chiếu lại toàn bộ 60 dự án và ba lượt lặp; sau đó phân tích Track 1 và độ nhạy ngân sách riêng. Báo cáo tạm này không thay thế kết quả cuối cùng.
'''
    save_bytes(out / "report/REPORT.md", text.encode())
    result = {"status": "EXPORTED_INTERIM", "exported_at": now(), "cutoff": cutoff.isoformat(),
        "paired_cases": count, "planned_raw_cases": 360, "distinct_projects": population,
        "condition_cases": dict(by_condition), "arms": len(rows), "incomplete_arms": errors,
        "report": str(out / "report/REPORT.md"), "source_record_sha256": provenance,
        "selection_sha256": digest(study / "model-selection.json"), "llm_calls": 0,
        "superiority": "NOT_ESTABLISHED_BY_INTERIM_ANALYSIS"}
    save(out / "result.json", result)
    return result


def fmt(value):
    return "không xác định" if value is None else f"{value:.4f}"


def worker(job_file):
    job_file = Path(job_file)
    lock = job_file.with_suffix(".lock").open("a+")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    job = load(job_file)
    try:
        for name, expected in load(job_file.parent / "export-source.json")["files"].items():
            if digest(ROOT / name) != expected:
                raise ValueError("Frozen reporting source changed")
        job.update(status="WAITING", pid=os.getpid(), worker_started_at=now())
        save(job_file, job)
        due = instant(job["scheduled_at"])
        while True:
            remaining = (due - datetime.now(timezone.utc)).total_seconds()
            if remaining <= 0:
                break
            job.update(heartbeat_at=now(), remaining_seconds=round(remaining))
            save(job_file, job)
            time.sleep(min(30, remaining))
        job.update(status="EXPORTING", export_started_at=now())
        save(job_file, job)
        result = export(job["study"], job_file.parent / "output", due)
        job.update(status="EXPORTED", completed_at=now(), result=result)
        save(job_file, job)
    except BaseException as exc:
        job.update(status="FAILED", error_type=type(exc).__name__, error=str(exc), updated_at=now())
        save(job_file, job)
        raise
    finally:
        lock.close()


def launch(job_file):
    job_file = Path(job_file).resolve()
    job = load(job_file)
    if job.get("pid"):
        try:
            os.kill(job["pid"], 0)
            return {"status": "ALREADY_RUNNING", "job": str(job_file), "pid": job["pid"]}
        except ProcessLookupError:
            pass
    if job.get("status") == "EXPORTED":
        return {"status": "ALREADY_EXPORTED", "job": str(job_file)}
    source = job_file.parent / "source_bundle"
    if not (source / "source_manifest.json").exists():
        freeze(source)
        target = source / "scripts/export_interim_sbom_report.py"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(__file__, target)
        files = load(source / "source_manifest.json")["files"]
        files["scripts/export_interim_sbom_report.py"] = digest(target)
        save(job_file.parent / "export-source.json", {"files": files})
    environment = {k: v for k, v in os.environ.items() if k in {"PATH", "LANG", "LC_ALL", "TZ"}}
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    log = os.open(job_file.parent / "exporter.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        process = subprocess.Popen([sys.executable, "-B", str(source / "scripts/export_interim_sbom_report.py"),
            "--worker", "--job", str(job_file)], cwd=source, env=environment,
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    finally:
        os.close(log)
    CHILDREN.append(process)
    result = {"pid": process.pid, "scheduled_at": job["scheduled_at"], "job": str(job_file), "llm_calls": 0}
    save(job_file.parent / "launch.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job")
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--now", action="store_true")
    parser.add_argument("--study", default="runs/m25-agent-study-v2")
    parser.add_argument("--out")
    args = parser.parse_args()
    if args.worker:
        worker(args.job)
    elif args.now:
        if not args.out:
            parser.error("--now requires --out")
        result = export(args.study, args.out, datetime.now(timezone.utc))
        print(json.dumps({k: v for k, v in result.items() if k != "source_record_sha256"}, ensure_ascii=False))
    elif args.job:
        print(json.dumps(launch(args.job), ensure_ascii=False))
    else:
        parser.error("Use --job to schedule an existing job, or --now --out for an immediate checkpoint")


if __name__ == "__main__":
    main()

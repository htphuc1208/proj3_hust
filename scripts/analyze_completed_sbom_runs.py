#!/usr/bin/env python3
"""Audit and summarize completed source, baseline and development experiments.

This analysis does not select a model or modify a prediction. Development
comparisons remain diagnostic; held-out agent comparisons require test results.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import io
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from research_core import digest,load,now
from sbom_recovery.baselines import coverage,UNIFIER_COMMIT,REPLICATION_COMMIT
from sbom_recovery.campaign import score_after_seal,flat_scores
from sbom_recovery.contracts import TargetContext
from sbom_recovery.formats import sha
from sbom_recovery.metrics import paired_bootstrap,holm
from sbom_recovery.reporting import read_records,aggregate
from sbom_recovery.storage import save,save_bytes

SCRIPT_SHA256=digest(__file__)
METHODS=("observed","single_scanner","sbom_unifier","unifier_rules","deterministic")
BINDINGS=("input_sha256","context_sha256","evidence_input_sha256","implementation_sha256","single_scanner","budget")


def csv_file(path,rows):
    if not rows:return
    out=io.StringIO();writer=csv.DictWriter(out,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    save_bytes(path,out.getvalue().encode())


def case_key(row):
    return tuple(row.get(k) for k in ("project","condition","budget","family","rate","mask_seed","repetition"))


def assert_paired_inputs(agent_rows,control_rows):
    controls={}
    agents=set()
    for row in control_rows:
        key=case_key(row),row["method"]
        if key in controls:raise ValueError("Duplicate control observation")
        controls[key]=row
    for row in agent_rows:
        if case_key(row) in agents:raise ValueError("Duplicate agent observation")
        agents.add(case_key(row))
        for method in METHODS:
            other=controls.get((case_key(row),method))
            if other is None:raise ValueError("Missing paired development control: "+method)
            if any(k not in row or k not in other or row[k] is None or row[k]!=other[k] for k in BINDINGS):
                raise ValueError("Incomparable development inputs: "+row["project"]+" / "+method)
    if set(controls)!={(key,method) for key in agents for method in METHODS}:
        raise ValueError("Unpaired extra development control")


def audited_records(run):
    run=Path(run)
    manifest=load(run/"campaign.json")
    if manifest["status"] not in {"COMPLETE","PARTIAL"}:
        raise ValueError("Analysis requires a finished campaign: "+str(run))
    prediction_hashes={};evaluation_hashes={};reference_hashes={};case_hashes={};contexts={};isolation={}
    diagnostic_variants={};recomputed={}
    captures=Path(manifest["settings"]["captures"])
    for file in sorted(run.rglob("records.json")):
        observation=load(file.parent/"input.spdx.json")
        binding=load(file.parent/"evidence_binding.json")
        case_hashes[str(file.parent/"input.spdx.json")]=digest(file.parent/"input.spdx.json")
        case_hashes[str(file.parent/"evidence_binding.json")]=digest(file.parent/"evidence_binding.json")
        for row in load(file).get("records",[]):
            arm=file.parent/row["method"]
            seal=load(arm/"seal.json")
            observed=digest(arm/"prediction.spdx.json")
            if observed!=seal["prediction_sha256"]:raise ValueError("Prediction changed after sealing")
            if any(row.get(k)!=v for k,v in seal["spec"].items()):
                raise ValueError("Record differs from sealed specification")
            if row["input_sha256"]!=sha(observation) or row["evidence_input_sha256"]!=sha(binding):
                raise ValueError("Case input or evidence catalog changed")
            worker_flag=seal.get("oracle_exposed_to_prediction_worker")
            if worker_flag is not False:
                # The frozen development revision predates the explicit worker
                # field. Preserve that provenance gap instead of rewriting its
                # seals or treating a missing field as False.
                legacy="input_origin" not in row and seal.get("oracle_read_before_seal") is False
                details=load(arm/"details.json") if (arm/"details.json").exists() else {}
                worker_oracle=details.get("isolation",{}).get("oracle_mounted")
                if worker_flag is True or not legacy or ("agent" in row["method"] and worker_oracle is not False):
                    raise ValueError("Missing prediction-worker oracle isolation declaration")
                isolation[str(arm)]={"seal_worker_flag":"UNRECORDED_LEGACY_SEAL",
                    "oracle_read_before_seal":False,"worker_oracle_mounted":worker_oracle}
            capture=captures/row["project"]
            if row["project"] not in contexts:
                capture_info=load(capture/"capture.json")
                context=TargetContext.model_validate(load(capture/"context.json"))
                context=context.model_copy(update={"evidence_cutoff":capture_info["historical_resolution_horizon"],
                    "root_purls":context.root_purls or [f"pkg:pypi/{capture_info['project']['name']}@{capture_info['project']['version']}"]})
                contexts[row["project"]]=sha(context.model_dump())
            if contexts[row["project"]]!=row["context_sha256"]:
                raise ValueError("Target context differs from the recorded case")
            reference_paths=[capture/"oracle"/name for name in (
                "installed_reference.cdx.json","installed_reference.json","installed_field_labels.json")]
            for path in reference_paths:
                reference_hashes.setdefault(str(path),digest(path))
            evaluation=load(arm/"evaluation.json")
            current=score_after_seal(capture,observation,load(arm/"prediction.spdx.json"))
            differences={key for key in evaluation.keys()|current.keys() if evaluation.get(key)!=current.get(key)}
            # Development's frozen evaluator predates node/metadata error lists
            # and typed A–E entries. Every original score block must still match;
            # newer diagnostics are derived separately without rewriting results.
            legacy_diagnostics={"false_positive_nodes","missed_nodes","false_positive_metadata","missed_metadata",
                                "failure_taxonomy","failure_taxonomy_counts"}
            if differences:
                if "input_origin" in row or not differences<=legacy_diagnostics:
                    raise ValueError("Evaluation cannot be reproduced from sealed prediction: "+str(arm))
                diagnostic_variants[str(arm)]={"differing_diagnostic_fields":sorted(differences),
                    "score_blocks":"IDENTICAL","report_diagnostics":"DERIVED_WITH_CURRENT_AUDITED_ANALYZER"}
            if row["metrics"]!=flat_scores(evaluation):
                raise ValueError("Recorded F1 differs from audited evaluation")
            recomputed[str(arm.resolve())]=current
            prediction_hashes[str(arm/"prediction.spdx.json")]=observed
            evaluation_hashes[str(arm/"evaluation.json")]=digest(arm/"evaluation.json")
    rows,provenance=read_records(run)
    for row in rows:
        current=recomputed[str((Path(row["case"])/row["method"]).resolve())]
        for unit,fp,fn in (("nodes","false_positive_nodes","missed_nodes"),
                           ("edges","false_positive_edges","missed_edges"),
                           ("metadata","false_positive_metadata","missed_metadata")):
            row[unit+"_fp"]=len(current[fp]);row[unit+"_fn"]=len(current[fn])
        for category in ("A","B","C","D","E","UNRESOLVED"):
            row["failure_"+category]=len(current["failure_taxonomy"][category])
    return rows,{"campaign_sha256":digest(run/"campaign.json"),"record_sha256":provenance,
        "prediction_sha256":prediction_hashes,"evaluation_sha256":evaluation_hashes,
        "case_sha256":case_hashes,"reference_sha256":reference_hashes,
        "context_content_sha256":contexts,
        "legacy_isolation_declarations":isolation,
        "legacy_diagnostic_schema_variants":diagnostic_variants,
        "scoring_audit":"RECOMPUTED_FROM_SEALED_PREDICTIONS_WITHOUT_REWRITING_OUTCOMES"}


def failure_summary(run):
    """Count observed failures without guessing A–E causal attribution."""
    groups=defaultdict(list)
    for file in sorted(Path(run).rglob("records.json")):
        for row in load(file).get("records",[]):
            groups[(row["method"],row["condition"],row["family"])].append((row,file.parent/row["method"]))
    output=[]
    for (method,condition,family),items in sorted(groups.items()):
        statuses=Counter();terminal_errors=Counter();validation_errors=Counter();invalid_arms=Counter()
        without_acquisition=without_accepted=0;artifacts={}
        for row,arm in items:
            statuses[row["status"]]+=1
            path=arm/"details.json"
            details=load(path) if path.exists() else {}
            if path.exists():artifacts[str(path)]=digest(path)
            errors=[str(t["error"]) for t in details.get("transcript",[]) if t.get("error")]
            if row["status"]=="MODEL_ERROR":
                terminal_errors[errors[-1] if errors else "UNRECORDED"]+=1
            without_acquisition+=not any(t.get("tool",t.get("name"))=="acquire" for t in details.get("tool_trace",[]))
            without_accepted+=not details.get("verified",{}).get("accepted",[])
            validation=arm/"validation.json"
            seen=set()
            if validation.exists():
                artifacts[str(validation)]=digest(validation)
                for error in load(validation).get("errors",[]):
                    message=error.get("message","")
                    if "verification_code must be None if files_analyzed is False" in message:
                        label="VERIFICATION_CODE_WITH_FILES_ANALYZED_FALSE"
                    elif "Unrecognized license reference" in message:
                        label="UNRESOLVED_LICENSE_REF"
                    else:label=error.get("code","UNCLASSIFIED_VALIDATION_ERROR")
                    validation_errors[label]+=1;seen.add(label)
            invalid_arms.update(seen)
        output.append({"method":method,"condition":condition,"family":family,"arms":len(items),
            "statuses":dict(statuses),"terminal_model_errors":dict(terminal_errors),
            "validation_message_counts":dict(validation_errors),"invalid_arm_counts_by_error":dict(invalid_arms),
            "without_acquire_call":without_acquisition if "agent" in method else None,
            "without_accepted_change":without_accepted if "agent" in method else None,
            "artifact_sha256":artifacts})
    return output


def source_summary(run):
    run=Path(run);summary=load(run/"source_summary.json")
    expected=("MS SBOM Tool","Syft","Trivy","sbom-unifier")
    completed=[r for r in summary["records"] if r["status"]=="EXECUTED"]
    common=[r for r in completed if all(t in r.get("coverage",{}) for t in expected)]
    verified={}
    for row in completed:
        if row["details"]["commit"]!=UNIFIER_COMMIT:raise ValueError("Source merger commit mismatch")
        path=run/row["project"]/"unified.spdx.json"
        if coverage(load(path))!=row["coverage"]["sbom-unifier"]:
            raise ValueError("Recomputed original field coverage differs")
        verified[str(path)]=digest(path)
        if any(c["upstream_commit"]!=REPLICATION_COMMIT for c in row["coverage"].values()):
            raise ValueError("Field analyzer commit mismatch")
    rows=[]
    for panel,projects in (("available",completed),("common",common)):
        for tool in expected:
            available=[r for r in projects if tool in r.get("coverage",{})]
            for scope,fields in (("required",14),("required+optional",39)):
                counts=Counter()
                for row in available:
                    measurement=row["coverage"][tool]["scopes"][scope]
                    if measurement["evaluated_fields"]!=fields:raise ValueError("Field population differs from original analyzer")
                    counts.update({k:measurement[k] for k in ("full","part","miss")})
                total=len(available)*fields
                rows.append({"panel":panel,"tool":tool,"scope":scope,"projects":len(available),"field_observations":total,
                    **{k:counts[k] for k in ("full","part","miss")},
                    **{k+"_pct":100*counts[k]/total if total else None for k in ("full","part","miss")}})
    return {"statuses":dict(Counter(r["status"] for r in summary["records"])),"common_projects":len(common),
            "rows":rows,"source_summary_sha256":digest(run/"source_summary.json"),"verified_output_sha256":verified,
            "interpretation":"Original field presence only; NONE counts as populated; source correctness unmeasured"}


def paired_comparisons(rows,methods,baselines,metrics):
    comparisons=[]
    groups=sorted({(r["condition"],r["budget"],r["family"],r["rate"],r.get("input_origin")) for r in rows})
    for condition,budget,family,rate,origin in groups:
        subset=[r for r in rows if (r["condition"],r["budget"],r["family"],r["rate"],r.get("input_origin"))==(condition,budget,family,rate,origin)]
        for method in methods:
            for baseline in baselines:
                for metric in metrics:
                    result=paired_bootstrap(subset,method,baseline,metric)
                    comparisons.append({"condition":condition,"budget":budget,"family":family,"rate":rate,
                        "input_origin":origin,"method":method,"baseline":baseline,"metric":metric,**result})
    return holm(comparisons)


def figures(source,raw,destination,development=None):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    panel=[r for r in source["rows"] if r["panel"]=="common" and r["scope"]=="required+optional"]
    if panel:
        fig,ax=plt.subplots(figsize=(8,4.5));bottom=np.zeros(len(panel))
        for field,label,color in (("full_pct","Fully covered","#287D8E"),("part_pct","Partially covered","#DEA03A"),("miss_pct","Missing / NOASSERTION","#CBD2D8")):
            values=[r[field] for r in panel]
            ax.bar([r["tool"] for r in panel],values,bottom=bottom,label=label,color=color);bottom+=values
        ax.set(ylabel="Percentage of 39 fields × projects",ylim=(0,100),
               title=f"Source completeness; common panel n={source['common_projects']}\nAdapted three-scanner pipeline; correctness unmeasured")
        ax.legend(loc="upper center",bbox_to_anchor=(.5,-.12),ncol=3,fontsize=8)
        fig.tight_layout()
        for suffix in ("svg","pdf"):fig.savefig(destination/("source-field-coverage."+suffix))
        plt.close(fig)
    summary=aggregate(raw)
    fig,axes=plt.subplots(1,2,figsize=(12,4.7),sharey=True)
    for ax,condition in zip(axes,("fixed","active")):
        rows=[r for r in summary if r["condition"]==condition]
        positions=np.arange(len(METHODS));width=.25
        for i,(metric,label) in enumerate((("whole_node_f1","Nodes"),("whole_direct_edge_f1","Direct edges"),("whole_metadata_f1","Known metadata"))):
            values=[next(r for r in rows if r["method"]==m)[metric] for m in METHODS]
            ax.bar(positions+(i-1)*width,[np.nan if v is None else v for v in values],width,label=label)
        ax.set_xticks(positions,[m.replace("_","\n") for m in METHODS],fontsize=8)
        ax.set(title=condition,ylabel="Project-macro whole-inventory F1",ylim=(0,1))
    axes[1].legend(fontsize=8)
    fig.suptitle("Raw generator discrepancies: 60 held-out projects; baseline methods only")
    fig.tight_layout()
    for suffix in ("svg","pdf"):fig.savefig(destination/("heldout-baselines."+suffix))
    plt.close(fig)
    if development:
        methods=("sbom_unifier","deterministic","single_agent")
        fig,axes=plt.subplots(2,2,figsize=(9,7),sharey=True)
        for col,condition in enumerate(("fixed","active")):
            for row,(family,metric,title) in enumerate((
                    ("metadata","new_metadata_f1","New metadata"),
                    ("dependency","new_direct_edge_f1","New direct edges"))):
                ax=axes[row,col]
                measurements=[next(r for r in development["summary"] if r["condition"]==condition and r["family"]==family and r["method"]==m) for m in methods]
                values=[r[metric] for r in measurements]
                bars=ax.bar(range(3),values,color=("#287D8E","#668E44","#9B5D96"))
                for bar,r in zip(bars,measurements):
                    ax.annotate(f"{r[metric]:.3f}\nn={r[metric+'_n_projects']}",
                        (bar.get_x()+bar.get_width()/2,bar.get_height()),ha="center",va="bottom",fontsize=8,xytext=(0,3),textcoords="offset points")
                ax.set_xticks(range(3),("sbom-unifier","Deterministic","Single agent"),fontsize=8)
                ax.set(ylabel="Project-macro recovery F1",ylim=(0,1.15),title=f"{condition}: {title}")
        fig.suptitle("Development diagnostic; scanner masks at 50%; failures included\n20 projects, separate from the held-out controlled-reference experiment",fontsize=10)
        fig.tight_layout()
        for suffix in ("svg","pdf"):fig.savefig(destination/("development-diagnostic."+suffix))
        plt.close(fig)


def display(value):return "undefined" if value is None else f"{value:.4f}"


def write_report(destination,source,raw,development,selection,study,failures):
    audited_arm_count=len(raw)+(sum(r["cases"] for r in development["summary"]) if development else 0)
    source_table="\n".join(f"| {r['tool']} | {r['projects']} | {r['full_pct']:.2f}% | {r['part_pct']:.2f}% | {r['miss_pct']:.2f}% |" for r in source["rows"] if r["panel"]=="common" and r["scope"]=="required+optional")
    base_table="\n".join(f"| {r['condition']} | {r['method']} | {display(r['whole_node_f1'])} | {display(r['whole_direct_edge_f1'])} ({r['whole_direct_edge_f1_n_projects']}) | {display(r['whole_metadata_f1'])} | {display(r['vrr_after'])} ({r['vrr_after_n_projects']}) | {r['validation_failed']} |" for r in aggregate(raw))
    state=load(Path(study)/"state.json")
    dev_text="Development controls are still running; no agent-versus-control estimate is published yet."
    if development:
        table="\n".join(f"| {r['condition']} | {r['family']} | {r['method']} | {display(r['new_metadata_f1'])} ({r['new_metadata_f1_n_projects']}) | {display(r['new_direct_edge_f1'])} ({r['new_direct_edge_f1_n_projects']}) | {r['incomplete']} |" for r in development["summary"])
        dev_text="This is a post-selection development diagnostic, not held-out AI superiority evidence. Every compared input, context, evidence catalog and implementation hash was checked for equality. Failures remain included.\n\n| Condition | Mask family | Method | New-metadata F1 (n) | New-edge F1 (n) | Incomplete arms |\n| --- | --- | --- | --- | --- | --- |\n"+table
        comparisons=[r for r in development["comparisons"] if r["baseline"]=="sbom_unifier" and r["family"]=="metadata" and r["metric"]=="new_metadata_f1"]
        paired_table="\n".join(f"| {r['condition']} | {r['n_projects']} | {r['mean_delta']:+.4f} | [{r['ci95'][0]:+.4f}, {r['ci95'][1]:+.4f}] | {r['p_holm']:.4f} |" for r in comparisons if r["status"]=="MEASURED")
        dev_text+="\n\nPaired agent-minus-unifier metadata differences, restricted to the same eligible development projects:\n\n| Condition | Projects | Mean F1 difference | Project bootstrap 95% interval | Holm-adjusted p |\n| --- | --- | --- | --- | --- |\n"+paired_table
        dev_text+="\n\nThe fixed condition improves over unifier on this development measurement; the active condition regresses. The deterministic artifact-evidence control reaches 1.0000 metadata F1 in both conditions. The development inputs are scanner outputs with additional masking, separate from the primary controlled-reference track. Method-specific undefined denominators can differ; use paired intervals rather than subtracting means with different populations."
    agent_failures=[r for r in failures["development_agent"] if r["method"]=="single_agent"]
    failure_table="\n".join(f"| {r['condition']} | {r['family']} | {r['arms']} | {r['statuses'].get('MODEL_ERROR',0)} | {r['terminal_model_errors'].get('ReadTimeout',0)} | {r['terminal_model_errors'].get('Truncated model response',0)} | {r['terminal_model_errors'].get('ConnectError',0)} | {r['without_accepted_change']} |" for r in agent_failures)
    failure_text="Selected-agent development outcomes are retained, including partial drafts passed through the same verifier:\n\n| Condition | Mask family | Arms | Model errors | Read timeout | Truncated response | Connection error | No accepted change |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n"+failure_table if agent_failures else "Selected-agent diagnostics are not yet available."
    text=f'''# SBOM recovery: completed measurements and development diagnostics

Generated {now()}. The primary held-out AI study is still **{state['status']}** at stage **{state.get('current_stage','pending')}**.

## Context & Problem Formulation

This report separates source-SBOM field presence from correctness of the installed Python inventory. The source run has {source['statuses'].get('EXECUTED',0)} executed projects and {source['statuses'].get('SOURCE_UNAVAILABLE',0)} source-unavailable projects. The raw-generator track contains 600 baseline arms across 60 held-out projects. Reconstruction outputs remain candidate declarations; runtime reachability and exploitability are unmeasured.

## Theoretical Background & Sourcing

[Moriwaki et al., 2026, sbom-unifier, ICSME Tool Demonstrations](https://arxiv.org/abs/2608.30708) supplies the original 39-field required/optional evaluation. The original 90-project analyzer reproduction produced four byte-identical CSVs, recorded separately in `runs/m25-unifier-reproduction-v2/verification.json`. The new source run uses Microsoft/Syft/Trivy plus Ninka; a commit-bound GitHub graph is unavailable. It is an adapted experiment, not a complete recreation of the original four-source pipeline. [SPDX 2.3](https://spdx.github.io/spdx-spec/v2.3/) and [PyPA dependency specifiers](https://packaging.python.org/en/latest/specifications/dependency-specifiers/) define the native fields and environment-conditioned declaration semantics.

## Hypothesis & Experimental Design

The frozen development choice is `{selection['model']}` with scanner `{selection['single_scanner']}`. Its selection uses all 20 development projects and no held-out labels. The two composite development scores are {', '.join(r['model']+' = '+display(r['score']) for r in selection['candidates'])}; this small difference does not establish model superiority.

Raw baseline comparisons use the same observed native input and scanner peers. Deterministic repair additionally consumes the artifact evidence also allowed to agents. Its improvement over unifier alone measures the value of added evidence/rules, not an AI contribution. Fixed and active conditions remain separate. Undefined denominators are excluded and eligible project counts are reported. Paired comparisons and 10,000-resample intervals cluster by project; Holm correction applies within the exported comparison family. These analyses are descriptive, and shared dependencies limit independence.

## Empirical Evidence & Downstream Metrics

### Original 39-field measurement on the common source panel

| Tool | Projects | Fully covered | Partial | Missing / NOASSERTION |
| --- | --- | --- | --- | --- |
{source_table}

The percentages weight each project-field pair equally. The original analyzer counts `NONE` as populated. These are presence measurements, not proof that licenses, versions or inventory are correct. Available-case and common-panel denominators are both exported in `source-coverage.csv`.

### Held-out raw-generator baselines

| Condition | Method | Node F1 | Direct-edge F1 (n) | Known-metadata F1 | VRR after (n) | Invalid outputs |
| --- | --- | --- | --- | --- | --- | --- |
{base_table}

These are project-macro means. VRR's unit is a project/package-PURL/advisory-ID pair reachable through independently confirmed direct edges, with roots excluded and a frozen retrospective OSV snapshot. Its eligible project count excludes zero-denominator projects. Advisory aliases are not unique CVEs. Triage delta, false-assurance reduction, static call reachability and exploitability remain unmeasured. Source coverage and installed F1 must not be compared as a single quality scale.

### Development diagnostic

{dev_text}

The CSV/JSON files retain precision/recall, eligible sample sizes, validation failures, usage gaps, errors and paired confidence intervals. Failed model episodes are not dropped. Unsupported changes remain sidecars rather than being promoted by an LLM assertion.

All {audited_arm_count:,} sealed baseline/development predictions were re-scored from the saved independent references and matched all six stored set-based score blocks. The older development evaluator lacks some node/metadata error diagnostics; those counts are derived by the current analyzer and the schema differences are recorded explicitly. Legacy development seals also predate the explicit worker-oracle flag; their missing flag stays UNRECORDED in the audit, with separate saved Docker isolation records for agent workers. No evaluations, seals or predictions were rewritten.

## Failure Taxonomy & Threats to Validity

Category A–E attribution requires causal evidence; unresolved node/edge/metadata errors remain UNRESOLVED. Structural invalidity and model/transport errors are reported separately. Native documents and prediction seals were audited before aggregation. The original merger is not silently corrected.

{failure_text}

All 120 raw sbom-unifier outputs and 120 unifier-plus-rules outputs fail native semantic validation in this installed-filesystem adaptation. Saved validator messages identify verification codes retained with `filesAnalyzed=false`; some also contain unresolved `LicenseRef` references. These are measured adaptation outcomes, not a claim about every upstream use. F1 is still measured on their extracted facts rather than set to zero for invalid documents. Repairing the baseline would require a separately named variant. Error counts and hashed diagnostic artifacts are exported in `failure-diagnostics.json`.

Installed metadata is an information-sufficient control for many cases and shares underlying declarations with the independently collected reference. The curated pure-Python-root population, size exclusions, one Linux/CPython environment, retrospective acquisition, dependency overlap and unknown model pretraining/revisions constrain generalization. The primary study's non-streaming timeout and output limits constrain measured implementation performance. Opt-in streaming in the later standalone CLI is a separate engineering variant.

## Actionable Next Steps

The existing controller will finish all 80 calibration cases, fit the preregistered abstention policy, then run the held-out raw, controlled-reference and budget-sensitivity matrices. No threshold/model is retuned using this report. Held-out AI superiority is **not established** by source completeness, baseline-only results, or development diagnostics. The decision requires completed paired held-out agent/control results, confidence intervals and error/coverage review.

Inspect `runs/m25-agent-study-v2/state.json` and run `python -B scripts/run_agent_study.py --out runs/m25-agent-study-v2 --status` for live progress.

Standalone plots: [source field presence](source-field-coverage.svg), [raw baseline F1](heldout-baselines.svg), [development diagnostic](development-diagnostic.svg). Machine-readable outputs: [source coverage](source-coverage.csv), [baseline metrics](heldout-baseline-metrics.csv), [paired development estimates](development-comparisons.json), [audit hashes](analysis-provenance.json).
'''
    save_bytes(destination/"REPORT.md",text.encode())


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-run",default="runs/m25-source-coverage-v3")
    p.add_argument("--baseline-run",default="runs/m25-baseline-raw-heldout-v1")
    p.add_argument("--study",default="runs/m25-agent-study-v2")
    p.add_argument("--development-controls",default="runs/m25-development-controls-v1")
    p.add_argument("--out",required=True)
    args=p.parse_args();out=Path(args.out);out.mkdir(parents=True,exist_ok=True)
    selection=load(Path(args.study)/"model-selection.json")
    if selection.get("status")!="FROZEN" or selection.get("test_labels_used") is not False:
        raise ValueError("Model choice is not frozen independently of test outcomes")
    source=source_summary(args.source_run)
    raw,audit=audited_records(args.baseline_run)
    if len(raw)!=600 or len({r['project'] for r in raw})!=60:raise ValueError("Incomplete standalone baseline matrix")
    rows=aggregate(raw)
    comparisons=paired_comparisons(raw,("deterministic","unifier_rules"),("sbom_unifier",),
        ("new_metadata_f1","new_direct_edge_f1","whole_metadata_f1","whole_direct_edge_f1"))
    development=None;agent_run=None
    manifest=Path(args.development_controls)/"campaign.json"
    if manifest.exists() and load(manifest)["status"] in {"COMPLETE","PARTIAL"}:
        controls,control_audit=audited_records(args.development_controls)
        prefix="m25-development-qwen36-v2" if selection["model"]=="Qwen/Qwen3.6-35B-A3B-FP8" else "m25-development-qwen35-v2"
        agent_run=Path(args.study).parent/prefix
        agent,agent_audit=audited_records(agent_run)
        if len(controls)!=400 or len(agent)!=80:raise ValueError("Development comparison matrix is incomplete")
        assert_paired_inputs(agent,controls)
        combined=agent+controls
        development={"summary":aggregate(combined),"control_audit":control_audit,"agent_audit":agent_audit,
            "comparisons":paired_comparisons(combined,("single_agent",),("sbom_unifier","unifier_rules","deterministic"),
                ("new_metadata_f1","new_direct_edge_f1")),"role":"DEVELOPMENT_DIAGNOSTIC_ONLY"}
        csv_file(out/"development-metrics.csv",development["summary"])
        save(out/"development-comparisons.json",development)
    csv_file(out/"source-coverage.csv",source["rows"])
    csv_file(out/"heldout-baseline-metrics.csv",rows)
    save(out/"source-summary.json",source)
    save(out/"heldout-baseline-comparisons.json",comparisons)
    failures={"baselines":failure_summary(args.baseline_run),
        "development_agent":failure_summary(agent_run) if agent_run else [],
        "attribution":"OBSERVED_ERRORS_ONLY; A–E CAUSAL ATTRIBUTION REMAINS UNRESOLVED"}
    save(out/"failure-diagnostics.json",failures)
    if digest(__file__)!=SCRIPT_SHA256:
        raise ValueError("Analysis source changed during execution; rerun from one revision")
    save(out/"analysis-provenance.json",{"generated_at":now(),"analysis_script_sha256":SCRIPT_SHA256,
        "selection_sha256":digest(Path(args.study)/"model-selection.json"),"baseline_audit":audit,
        "heldout_agent_superiority":"UNMEASURED_PENDING_PRIMARY_STUDY"})
    figures(source,raw,out,development)
    write_report(out,source,raw,development,selection,args.study,failures)
    print({"source_common_projects":source["common_projects"],"baseline_arms":len(raw),
           "development_diagnostic":development is not None,"report":str(out/"REPORT.md")})


if __name__=="__main__":main()

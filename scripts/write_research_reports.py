#!/usr/bin/env python3
"""Render measured results and reference-only scope audit for human review."""
import argparse
import csv
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from research_core import digest, load, now, save
from packaging.utils import canonicalize_name
from scripts.run_scientific_validation import PILOTS


def table(headers, rows):
    return '\n'.join(['| ' + ' | '.join(headers) + ' |', '| ' + ' | '.join(['---'] * len(headers)) + ' |'] +
                     ['| ' + ' | '.join('UNDEFINED' if v is None else f'{v:.3f}' if isinstance(v, float) else str(v) for v in row) + ' |' for row in rows])


def reports(validation, controlled, ablation, reproduction):
    raw = load(Path(validation) / 'counterfactual_evidence_repair.json')
    masked = load(Path(controlled) / 'counterfactual_evidence_repair.json')
    knowledge = load(Path(ablation) / 'information_ablation_results.json')
    paper = load(Path(reproduction) / 'reproduction_results.json')
    b4 = load(Path(reproduction) / 'b4_comparison.json')
    reference_rows = []
    for project, _, reference in PILOTS:
        gold = load(ROOT / reference / 'ground_truth.json')
        app = {n['purl'] for n in gold['nodes']}
        inspection = load(ROOT / reference / 'pip_inspect.json')
        installed = {f"pkg:pypi/{canonicalize_name(r['metadata']['name'])}@{r['metadata']['version']}" for r in inspection['installed']}
        for generator in ('syft', 'cyclonedx'):
            scope = load(Path(validation) / project / generator / 'scope.json')
            for row in scope['components']:
                identity = row['canonical_identity']
                status = 'APPLICATION_REFERENCE_MEMBER' if identity in app else 'INSTALLED_OUTSIDE_APPLICATION_CLOSURE' if identity in installed else 'NOT_OBSERVED_IN_INSTALLED_REFERENCE' if identity else 'INVENTORY_OR_UNKNOWN_IDENTITY'
                reference_rows.append({'project': project, 'generator': generator, 'original_ref': row['original_ref'],
                    'canonical_identity': identity, 'inference_artifact_kind': row['artifact_kind'], 'inference_role': row['role'],
                    'evaluation_only_reference_status': status, 'provenance': reference + '/pip_inspect.json'})
    csv_path = Path(validation) / 'scope_reference_audit.csv'
    with csv_path.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(reference_rows[0]))
        writer.writeheader()
        writer.writerows(reference_rows)
    for run in (validation, controlled):
        source = load(Path(run) / 'counterfactual_evidence_repair.json')
        total = sum(p['regimes']['partial']['baselines']['B3']['whole_graph']['tp'] for p in source['projects'])
        repaired = sum(len(p['interventions']['recovered_with_wheel']) + len(p['interventions']['recovered_with_sdist']) for p in source['projects'])
        remaining = sum(len(p['interventions']['still_missing']) for p in source['projects'])
        save(Path(run) / 'ai_feasibility.json', {'population': 'Exact-version reference edges in three pilots',
            'data_kind': source['data_kind'], 'A_observed_or_deterministically_recovered_with_partial_evidence': total,
            'B_recovered_with_additional_public_evidence': repaired, 'remaining_unresolved': remaining,
            'C_structurally_underdetermined': 'Not observed in this edge-only cohort; frequency not established for missing-version reconstruction',
            'D_unrecoverable_from_permitted_information': 'Not established; bounded failures cannot prove impossibility',
            'security_consequences': 'UNMEASURED; no new advisory/exploitability evaluation',
            'evaluation_cost': 'See per-arm inference timestamps and public metadata/build attempt logs; HTTP-call totals unmeasured',
            'ml_training_authorized': False})
    def comparison(report):
        rows=[]
        for p in report['projects']:
            for regime in ('partial','wheel','sdist'):
                s=p['regimes'][regime]['baselines']['B3']['whole_graph']
                rows.append([p['project'],regime]+[s[k] for k in ('tp','fp','fn','precision','recall','f1')])
        return table(['Project','Evidence','TP','FP','FN','Precision','Recall','F1'],rows)
    controls = table(['Project','TP','FP','FN','Precision','Recall','F1'],[[p['project']]+[p['positive_control']['whole_graph'][k] for k in ('tp','fp','fn','precision','recall','f1')] for p in raw['projects']])
    rows=[]
    for name, arms in knowledge['results'].items():
        for arm, result in arms.items():
            rows.append([name,arm,len(result['contexts']),len(result['must']),len(result['possible']),result['must_score']['recall']])
    content=f'''# M2.3 Scientific Validation Report

## Context & Problem Formulation

Reconstruct candidate direct package dependencies from incomplete observations under declared target context. These measurements concern Level 1 package graphs only. Three legacy PyPI-installation pilots are evaluated; their recorded repository commits do not establish that a Git checkout was built. Installation timestamps remain UNKNOWN. No cohort expansion, model training or agent API run was performed.

The major correction is that the old Syft normalizer discarded declared dependency edges and promoted file inventory to package identities. Raw Syft inputs actually contain application-reference edges: requests 4/4, requests-cache 13/13, httpbin 29/31. These counts come from preserving and aligning raw relationships, not from changing the oracle.

## Theoretical Background & Sourcing

Independent installed METADATA supplies environment-conditioned declared dependency labels, not runtime behavior. PEP 508 marker/extras semantics and Core Metadata Dynamic rules follow [PyPA dependency specifiers](https://packaging.python.org/en/latest/specifications/dependency-specifiers/) and [PyPA Core Metadata](https://packaging.python.org/en/latest/specifications/core-metadata/). CycloneDX output validation uses frozen official 1.5 schemas in `research/schemas/`. Project protocol: `research/PROTOCOL.md`. No-path remains UNKNOWN.

## Hypothesis & Experimental Design

Test whether missing public metadata explains remaining FN while freezing input, context, resolver, evaluator and oracle. Inference runs without network or oracle mounts. Acquisition uses sorted observed exact identities. Snapshot scope is explicitly PARTIAL_CANDIDATE_UNIVERSE. Legacy candidate collection had a hard-coded cohort; its selection independence cannot be established retrospectively.

Keep raw-generator evaluation and controlled source-declaration masking separate. The controlled track reproduces the historical ten-FN condition but does not represent actual Syft omissions. Additional metadata is obtained publicly: wheel bytes verified by official digest; flasgger PKG-INFO is dynamic/insufficient, no index Core Metadata is advertised, and a separate no-network backend build produces METADATA. Target-installation wheels are not used by the provider.

## Empirical Evidence & Downstream Metrics

### Raw-generator track — B3 whole-graph metrics

{comparison(raw)}

Partial metadata already recovers one of httpbin's two original missing edges. The sdist intervention recovers the other. The wheel intervention does not recover any additional edge on the preserved raw graphs because the four requests edges were already present.

### Controlled source-masking track — historical FN repair

{comparison(masked)}

Four historical FN disappear after public wheel acquisition; six disappear after independently derived sdist metadata. This supports an evidence-coverage explanation for these ten controlled failures. It does not prove zero algorithmic failures or necessity/superiority of ML.

### Same-scope positive control

{controls}

The remaining CycloneDX-py false positive is mistune@3.4.0 → typing-extensions@4.16.0 in httpbin. Installed metadata restricts it to Python <3.11; the recorded environment is Python 3.11.16. It is retained as a false positive, not removed as tooling. Bootstrap-source edges outside the application closure have explicit exclusion records.

### Information ablation

{table(['Installation','Known environment / extras','Contexts','MUST','POSSIBLE','MUST recall'],rows)}

With requested SOCKS extras hidden, MUST loses the optional dependency. Platform knowledge does not change these particular real installations; platform effects are exercised only in labeled synthetic semantics tests. This is information sensitivity, not independent causal effects or calibrated probability.

VRR, OpenVEX triage delta, false-assurance reduction, static call reachability and exploitability are UNMEASURED in this milestone. No graph metric is substituted for these quantities.

## Failure Taxonomy & Threats to Validity

The controlled evidence failures fall under registry/metadata coverage (engineering taxonomy D); the six source-metadata cases additionally require independent backend acquisition. The A–D AI-feasibility decomposition is separate: controlled edges comprise 38 observed/deterministically recovered with partial evidence and 10 requiring additional public evidence. Raw graphs comprise 47 edges observed/recovered with partial evidence and one requiring additional sdist evidence. These are counts over 48 reference edges, not estimates for a general package population.

Construct validity: reference edges are declared installed dependencies, not imports or exploitability. Internal validity: historical snapshot selection, shared packaging parsers and UNKNOWN installation time limit conclusions; candidate uniqueness is not installation proof. External validity: three PyPI pilots with observed exact versions do not represent missing-version ambiguity, broad applications or other ecosystems. The extra synthetic scanner component `my-test-package` is retained as an unknown-role distribution candidate rather than promoted to verified application membership.

Some evidence queries fail (e.g. an artifact discovered inside scanner inventory has no public release). These remain in acquisition audit logs. No globally complete evidence or candidate-universe claim is made.

## Actionable Next Steps

Review `scope_audit.csv`, `scope_reference_audit.csv`, `edge_scope_audit.json` and per-edge counterfactual differences. Before the deferred expansion, add genuinely ambiguous version/node cases and separate scanner input modes. ML remains unauthorized. Compare any future evidence-selection method against deterministic fixed-order, cheapest-source and information-gain strategies under equal budgets.

Artifacts: raw run `{validation}`; controlled run `{controlled}`; information ablation `{ablation}`. Exact source/snapshot hashes, Docker commands and timestamps are recorded in their manifests and traces. New measurements are not pooled with legacy tables.
'''
    (ROOT/'research/validation_report.md').write_text(content)
    rows=[]
    for name,case in paper['cases'].items():
        for scanner,record in case['scanners'].items():
            score=record.get('author_label_agreement') or {}
            fresh=record.get('fresh_installed_component_score') or {}
            rows.append([name,scanner,record['status'],record.get('component_count'),score.get('precision'),score.get('recall'),fresh.get('recall')])
    b4rows=[]
    for name,record in b4.items():
        edge=record['edge_evaluation']['whole_graph']
        b4rows.append([name,record['component_evaluation']['tp']]+[edge[k] for k in ('tp','fp','fn','precision','recall','f1')])
    (ROOT/'research/reproduction_report.md').write_text(f'''# DSN 2024 Partial Reproduction and B4

## Context & Problem Formulation

Reproduce a bounded Python requirements subset of Yu, Song, Hu and Yin, *On the Correctness of Metadata-Based SBOM Generation: A Differential Analysis Approach*, IEEE/IFIP DSN 2024. This is the authors' crafted metadata benchmark, not their full 7,876-project population study or an in-the-wild cohort.

## Theoretical Background & Sourcing

[Paper](https://cs.ucr.edu/~heng/pubs/sbom-dsn24.pdf), Sections V-H / VII and Table III; [benchmark](https://github.com/DeepBitsTechnology/sbom-benchmark), commit `{paper['paper']['benchmark_commit']}`. The paper recommends package-manager resolution; B4 uses [pip dry-run/report](https://pip.pypa.io/en/stable/cli/pip_install/). All methods remain candidate resolution rather than target-installation proof.

## Hypothesis & Experimental Design

Entrypoints are the unchanged `python/req/requirements.txt` and `r.txt`, with their referenced files, excluding oracle labels from scanner workspaces. Toolchain: Syft 1.54.1 and Trivy 0.76.1, official archive checksums and binary hashes frozen in `research/toolchain.json`. Source-directory mode is evaluated; this differs from scanning installed environments. A pinned one-package synthetic parser control verifies that both scanners can emit a PyPI component. It establishes pipeline validity only.

The released groundtruth file provides {paper['author_label_count']} component/version labels for requirements.txt, including direct URLs and an original Windows path. They are parsed into identities without treating the Windows path as a current installation location. r.txt has no released per-entrypoint label, so no author-label precision/recall is invented. A new isolated install and pip inspect capture supply separate contemporary installed labels. No author edge labels are inferred from a component list.

## Empirical Evidence & Downstream Metrics

{table(['Input','Scanner','Status','Versioned components','Author precision','Author recall','Fresh install recall'],rows)}

Both scanners recognize requests==2.31.0 in the synthetic parser positive control. Both produce zero components on the two unchanged DSN source inputs under the pinned configuration. Independent contemporary installations succeeded: requirements.txt yields 54 reference distributions / 65 direct edges; r.txt yields 10 / 9. Their labels and all raw outputs/logs are preserved. Fresh edge scores are reported only against these independent captures.

For context, Table III of the paper reports Syft and Trivy precision 0.25 / recall 0.10. Our values do not reproduce that table: inputs are a released subset and tool versions, index state and environment differ. Report **PARTIALLY_REPRODUCED**, not an exact numerical reproduction. Undefined precision for an empty prediction is null, not 1.0.

### B4 operational check, separate information budget

{table(['Installation','Components TP','Edges TP','FP','FN','Precision','Recall','F1'],b4rows)}

B4 receives public manifest roots and a frozen finite wheelhouse, executes a dry run before oracle collection, then its report is converted to candidate edges. The reference is read separately from an installed venv and pip inspect. The two requests installations are contemporary controlled checks, not the historical DSN labels. Evidence completeness and runtime exploitability are not established by perfect scores.

## Failure Taxonomy & Threats to Validity

Source parser behavior and installed-environment scanning are distinct constructs. Contemporary registry resolution cannot recreate 2024 index state. Package-manager and reference parsing share PEP 508 libraries; this is an internal-validity limitation even though their inputs are independent. Source scanner defaults and unsupported/unpinned syntax limit identification; zero source components do not establish that the software has no dependencies. No new security advisory, VRR or exploitability experiment is included.

## Actionable Next Steps

Inspect the per-input logs and scanner controls before generalizing tool behavior. Historical-tool execution, Poetry/Pipfile cases, GitHub DG, Microsoft sbom-tool, the full population study and the 2026 topology replication remain unexecuted. B5/B6 and agent feasibility are deferred. No ML training is authorized.

Reproduction bundle: `{reproduction}`. Original artifact bytes, source commit, tool hashes, commands and per-experiment results are included. The Workbench presents these stored measurements.
''')
    matrix=[['B0','Observed SBOM','No enrichment','Observed edges only','Application graph + additions','Operational'],
            ['B1','Observed SBOM + same public snapshot','Ignores environment/extras; ablation','Unconditional candidates','Same evaluator','Operational'],
            ['B2','Observed SBOM + same public snapshot','Finite environment/extra superset','Possible edges; not calibrated','Same evaluator','Operational'],
            ['B3','Observed SBOM + declared target context + snapshot','PEP 508 + version matching','MUST/MAY/UNKNOWN; candidate provenance','Same evaluator','Operational'],
            ['B4','Manifest roots + environment + frozen public artifact set','Package-manager resolver','Hypothetical resolution; unresolved explicit','Independent installed reference; separate privileged budget','Operational'],
            ['B5','Declared graph + completeness evidence','Open-world triage','Missing path UNKNOWN','Security triage metrics','Deferred'],
            ['B6','External deps.dev graph','Generic remote resolution','Environment mismatch must be reported','Not target ground truth','Deferred']]
    with (ROOT/'research/baseline_matrix.csv').open('w',newline='') as f:
        writer=csv.writer(f)
        writer.writerow(['baseline','input_permissions','method','uncertainty','evaluation_scope','status','environment_requirements','computational_cost'])
        requirements = {'B0':'None for observation preservation','B1':'Ignored by design; context-free ablation',
                        'B2':'Declared finite plausible-context matrix','B3':'Declared target or explicitly bounded context set',
                        'B4':'Explicit interpreter, platform, roots, extras and frozen artifact set',
                        'B5':'Declared graph completeness and advisory assessment context',
                        'B6':'Remote generic environment, target mismatch must be documented'}
        for row in matrix:
            cost = 'Measured dry-run latency in b4_comparison.json; download/build cost separate' if row[0]=='B4' else 'Deferred / unmeasured' if row[0] in ('B5','B6') else 'Per-arm latency unmeasured; combined B0-B3 container interval recorded in inference traces'
            writer.writerow(row+[requirements[row[0]],cost])
    # Register every persisted artifact, including reporting sidecars. Registration
    # is an observed event; never substitute it for an unknown original creation time.
    for directory in map(Path, (validation, controlled, ablation, reproduction)):
        manifest = load(directory / 'run_manifest.json')
        for path in sorted(directory.rglob('*')):
            if not path.is_file() or 'public_cache' in path.parts or path.name == 'run_manifest.json':
                continue
            name = str(path.relative_to(directory))
            current = digest(path)
            if name in manifest['artifacts']:
                if manifest['artifacts'][name]['sha256'] != current:
                    raise ValueError('Registered artifact mutated: ' + str(path))
            else:
                manifest['artifacts'][name] = {'sha256': current, 'registered_at': now(),
                    'original_creation_timestamp': 'UNKNOWN unless independently recorded in content/stage trace'}
        manifest['reporting_completed_at'] = now()
        save(directory / 'run_manifest.json', manifest)
    print('Wrote validation_report.md, reproduction_report.md, baseline_matrix.csv and evaluation-only scope audit')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('validation','controlled','ablation','reproduction'):
        p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    reports(a.validation,a.controlled,a.ablation,a.reproduction)

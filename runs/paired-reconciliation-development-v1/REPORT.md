# Three-arm SBOM development comparison

## Context & Problem Formulation

This run compares the unmodified Syft observation, the existing deterministic repair policy, and that exact repair prediction followed by inactive-declaration reconciliation. All 20 roots are old development projects. Outputs are candidate declared graphs conditioned on the captured target/context; they do not attest deployed artifacts or executed code.

## Theoretical Background & Sourcing

[PyPA, Dependency specifiers](https://packaging.python.org/en/latest/specifications/dependency-specifiers/) supplies marker/extras/version semantics. [SPDX 2.3.1, Relationships](https://spdx.github.io/spdx-spec/v2.3.1/relationships-between-SPDX-elements/) defines direct/inverse dependencies. The policies are local engineering baselines, with no novelty or generalization claim. The original source and installed graph scopes remain distinct.

## Hypothesis & Experimental Design

The descriptive questions are what the existing additive policy restores and whether subsequent conservative reconciliation reduces known FP edges without removing known true edges. Methods have the same full, digest-bound top-level METADATA permissions, observation and context. No scanner peers, registries, oracle seeds or model calls are used. Existing additive field/component behavior and explicit-declaration conflict handling remain unchanged. Its identity changes are counted separately from native edge additions.

One network-disabled Docker worker per project shares one snapshot across all three arms. All 60 predictions are sealed and integrity checked before opening independent labels. Labels are bound to the frozen installed-reference manifest and original pip-inspect/install-report hashes. Contemporary capture-completion availability is used; historical METADATA availability is not asserted. Native invalidity and policy failures remain visible alongside extracted-fact scores. Policy time excludes shared preparation and final export checks; combined time includes the reused additive computation. Container elapsed time is recorded separately and is not a performance benchmark.

## Empirical Evidence & Downstream Metrics

Status: **COMPLETE_DEVELOPMENT_COMPARISON**, 20/20 scored projects. Precision, recall and F1 below use the same per-metric eligible projects across all arms, within the 11 projects whose reference contains edges. FP/FN counts use all scored projects, including the 9 empty-reference projects.

| Method | Precision | Recall | F1 | FP, all projects | FN, all projects |
| --- | ---: | ---: | ---: | ---: | ---: |
| Observed | 0.7888 | 0.9787 | 0.8702 | 42 | 4 |
| Additive | 0.7917 | 1.0000 | 0.8813 | 42 | 0 |
| Additive + reconciliation | 0.9053 | 1.0000 | 0.9464 | 17 | 0 |

Metric denominators: {'precision': 11, 'recall': 11, 'f1': 11}. Undefined scores remain undefined, never filled with a perfect score. Available-case means are retained separately in summary.json and must not be subtracted across different populations.

Additive stage graph-fact additions: {'KNOWN_TRUE': 4}; graph-fact removals: {}. Actual native edge additions: 4; changed identity references: 0. Graph-fact changes from identity correction are not relabeled as native edge additions.

Reconciliation graph-fact removals: {'KNOWN_FALSE': 25}; additions: {}. Actual native edge retractions: 25. KNOWN_TRUE removals are incorrect retractions; UNKNOWN labels cannot receive FP-removal credit. Per-project evaluations and stage-attribution.json retain each edge and label. Unknown assessments: 673. summary.json records the single operating point's retraction coverage/selective risk and explicit undefined denominators; there is no calibrated probability or threshold curve.

VRR, VEX triage delta, false-assurance reduction, static call paths and exploitability are **UNMEASURED**. No path means UNKNOWN. No inferential significance or agent-superiority claim is made from these development measurements. Standalone figures: [SVG](comparison.svg), [PDF](comparison.pdf).

## Failure Taxonomy & Threats to Validity

Known graph errors retain the existing A–E/UNRESOLVED accounting; errors without causal evidence remain UNRESOLVED. Contradiction evidence concerns inactive declarations, not an identified internal scanner bug. Construct validity stops at package declarations and PURL-pair graph facts. Shared standards libraries/underlying metadata, coordinate-conditioned identity, information-rich evidence and reuse of inspected development roots limit internal validity. Twenty selected Python roots, one environment, shared dependencies and empty graphs limit external validity. These are not 60 independent projects. Operational and native-validation statuses appear in summary.json.

## Actionable Next Steps

Preserve these results and the frozen M2.5 study. Diagnose discrepancies on development only. Implement and freeze the budgeted acquisition controls separately before testing LLM source selection at budgets 4/16. Freeze untouched roots and calibration/analysis before a new held-out evaluation. Independent human/discovery review and scanner-to-artifact scope correctness still gate the 30-case corpus expansion.

Replay with a fresh output path: `.venv/bin/python -B scripts/run_paired_reconciliation_development.py --out runs/paired-reconciliation-new`. Local captured targets, references and the pinned Docker image are required; hashes are not a complete portable replay bundle.

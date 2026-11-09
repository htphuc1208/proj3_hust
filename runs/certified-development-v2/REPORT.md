# Certified reconciliation V2 — development only

## Question and design

Do scoped completeness checks and executable certificates improve decisions
over strong metadata interpretation? These are old development roots, never a
held-out generalization experiment. Three conditions are separate: full metadata,
controlled context withholding, and controlled 50% metadata withholding (seed 42).
All arms share the same permitted bytes/context. The strong metadata control
shares the semantic trusted base; equality must not be marketed as superiority.

Each case runs in a network-disabled container with only frozen source, staged
evidence and output mounts. Oracle files, full targets, withheld bytes and hidden
legacy context are absent. Every prediction matrix is verified before references
are read. Historical deployment identity and runtime use are unmeasured.

## Results

Status: **COMPLETE_DEVELOPMENT**; 20 projects, 60 paired cases.

| Method | Available-case edge F1 | Known changes | Incorrect changes | Unknown changes |
| --- | ---: | ---: | ---: | ---: |
| observed | 0.4786 | 0 | 0 | 0 |
| legacy_additive | 0.4806 | 4 | 0 | 0 |
| legacy_reconciliation | 0.5797 | 45 | 0 | 0 |
| metadata_control | 0.4786 | 0 | 0 | 0 |
| certified_v2 | 0.4786 | 0 | 0 | 0 |

These descriptive means pool conditions and can have different denominators;
they are not valid method-effect contrasts. Per-condition results and paired
project contrasts with common cases are in summary.json. Zero denominators stay
null. Bootstrap/randomization use projects, 10,000 draws and Holm correction.

Certified V2 and the strong semantic control have identical native edge sets in
**60/60** cases.
Empirical advantage gate: **NOT_MET_EQUAL_STRONG_CONTROL**.

## Interpretation and limitations

Certificates establish derivations under trusted collector/context assertions;
they do not attest executable contents. Existing reference labels score unique
coordinates, not ambiguous physical occurrences. Shared package declarations and
standards libraries remain a common-error threat. Single-environment selected
roots and shared dependencies limit generalization. Controlled withholding is
not evidence of the prevalence of natural evidence loss.

No A* novelty, agent superiority, calibrated probability, exploitability or
security-triage improvement is established. No held-out roots were consumed.
Human audit forms are pending; an LLM review is not counted as a human review.

## Decision

If the strong control ties all cases, do not launch a tuned held-out accuracy
study for this version. Preserve the negative result and investigate whether
independently checkable certificates have a distinct, substantive research
question. This run alone does not establish that contribution.

Replay from frozen source with the recorded image and staged inputs; host paths
in execution.json document this execution, not a portable command. The worker
only requires /code, /job and /out mounts. See research/CERTIFIED_RECONCILIATION.md.

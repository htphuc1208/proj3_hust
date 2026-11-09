# Superseded analysis/comparator adapter

Predictions and original reports are preserved. The original common-F1 panel
used native reference edge counts, which include an artificial application-root
relationship; eligibility must use the scorer's coordinate graph. A separate
`runs/certified-analysis-v1` corrects this without changing predictions.

The legacy adapter also inherited V2's metadata-completeness restriction for
historical Metadata-Version 2.0. The final `runs/certified-development-v4` fixes
that comparator adaptation with a regression test. Use v4 as the final study.
V2 and strong-control graph predictions were not changed by these corrections.

# DSN 2024 Partial Reproduction and B4

## Context & Problem Formulation

Reproduce a bounded Python requirements subset of Yu, Song, Hu and Yin, *On the Correctness of Metadata-Based SBOM Generation: A Differential Analysis Approach*, IEEE/IFIP DSN 2024. This is the authors' crafted metadata benchmark, not their full 7,876-project population study or an in-the-wild cohort.

## Theoretical Background & Sourcing

[Paper](https://cs.ucr.edu/~heng/pubs/sbom-dsn24.pdf), Sections V-H / VII and Table III; [benchmark](https://github.com/DeepBitsTechnology/sbom-benchmark), commit `e6bcf23b2f4e384f9fc398793529583845612b63`. The paper recommends package-manager resolution; B4 uses [pip dry-run/report](https://pip.pypa.io/en/stable/cli/pip_install/). All methods remain candidate resolution rather than target-installation proof.

## Hypothesis & Experimental Design

Entrypoints are the unchanged `python/req/requirements.txt` and `r.txt`, with their referenced files, excluding oracle labels from scanner workspaces. Toolchain: Syft 1.54.1 and Trivy 0.76.1, official archive checksums and binary hashes frozen in `research/toolchain.json`. Source-directory mode is evaluated; this differs from scanning installed environments. A pinned one-package synthetic parser control verifies that both scanners can emit a PyPI component. It establishes pipeline validity only.

The released groundtruth file provides 52 component/version labels for requirements.txt, including direct URLs and an original Windows path. They are parsed into identities without treating the Windows path as a current installation location. r.txt has no released per-entrypoint label, so no author-label precision/recall is invented. A new isolated install and pip inspect capture supply separate contemporary installed labels. No author edge labels are inferred from a component list.

## Empirical Evidence & Downstream Metrics

| Input | Scanner | Status | Versioned components | Author precision | Author recall | Fresh install recall |
| --- | --- | --- | --- | --- | --- | --- |
| r | syft | RAN | 0 | UNDEFINED | UNDEFINED | 0.000 |
| r | trivy | RAN | 0 | UNDEFINED | UNDEFINED | 0.000 |
| requirements | syft | RAN | 0 | UNDEFINED | 0.000 | 0.000 |
| requirements | trivy | RAN | 0 | UNDEFINED | 0.000 | 0.000 |

Both scanners recognize requests==2.31.0 in the synthetic parser positive control. Both produce zero components on the two unchanged DSN source inputs under the pinned configuration. Independent contemporary installations succeeded: requirements.txt yields 54 reference distributions / 65 direct edges; r.txt yields 10 / 9. Their labels and all raw outputs/logs are preserved. Fresh edge scores are reported only against these independent captures.

For context, Table III of the paper reports Syft and Trivy precision 0.25 / recall 0.10. Our values do not reproduce that table: inputs are a released subset and tool versions, index state and environment differ. Report **PARTIALLY_REPRODUCED**, not an exact numerical reproduction. Undefined precision for an empty prediction is null, not 1.0.

### B4 operational check, separate information budget

| Installation | Components TP | Edges TP | FP | FN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| base | 5 | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| socks | 6 | 5 | 0 | 0 | 1.000 | 1.000 | 1.000 |

B4 receives public manifest roots and a frozen finite wheelhouse, executes a dry run before oracle collection, then its report is converted to candidate edges. The reference is read separately from an installed venv and pip inspect. The two requests installations are contemporary controlled checks, not the historical DSN labels. Evidence completeness and runtime exploitability are not established by perfect scores.

## Failure Taxonomy & Threats to Validity

Source parser behavior and installed-environment scanning are distinct constructs. Contemporary registry resolution cannot recreate 2024 index state. Package-manager and reference parsing share PEP 508 libraries; this is an internal-validity limitation even though their inputs are independent. Source scanner defaults and unsupported/unpinned syntax limit identification; zero source components do not establish that the software has no dependencies. No new security advisory, VRR or exploitability experiment is included.

## Actionable Next Steps

Inspect the per-input logs and scanner controls before generalizing tool behavior. Historical-tool execution, Poetry/Pipfile cases, GitHub DG, Microsoft sbom-tool, the full population study and the 2026 topology replication remain unexecuted. B5/B6 and agent feasibility are deferred. No ML training is authorized.

Reproduction bundle: `runs/m23-dsn-b4-v2`. Original artifact bytes, source commit, tool hashes, commands and per-experiment results are included. The Workbench presents these stored measurements.

# M2.5 — Evidence-grounded agentic SBOM recovery

## Context & Problem Formulation

The implementation estimates a candidate graph and field repairs from an observed SBOM, an explicit environment, and permitted evidence. An arbitrary observed SBOM is not assumed to be a subgraph of the reference. The original native document remains immutable. Proposed, evidence-supported, and target-verified changes are distinguished.

The primary experimental scope is **all top-level installed Python distributions** and their declared direct requirements, evaluated under the captured environment and known extras. The application root is recorded separately. Provisioning distributions belong to the installed inventory; vendored and test-fixture metadata do not become independently installed distributions. Runtime imports, call paths and exploitability are outside this scope.

Source inventory is a separate track. Its 39-field SPDX coverage cannot certify installed inventory or be compared numerically with a different population of records without qualification.

## Theoretical Background & Sourcing

- Moriwaki et al., 2026, *sbom-unifier: Integration Framework for Heterogeneous SBOMs*, ICSME Tool Demonstrations: <https://arxiv.org/abs/2608.30708>. The original analyzer measures field presence, not correctness. Pinned source and replication commits are in `configs/agent-recovery-v1.json` and `research/agent_toolchain.json`.
- Bouzenia et al., 2025, *RepairAgent*, ICSE: <https://doi.org/10.1109/ICSE55347.2025.00157>. It motivates bounded tool orchestration and validation; its code-repair results are not SBOM results.
- PyPA dependency semantics: <https://packaging.python.org/en/latest/specifications/dependency-specifiers/>. Markers and extras are evaluated per parent; unobserved environment variables remain unknown. Registry/source claims cannot activate an extra in target-verified evidence.
- SPDX 2.3: <https://spdx.github.io/spdx-spec/v2.3/>; CycloneDX: <https://cyclonedx.org/docs/>; PURL: <https://github.com/package-url/purl-spec>. Native records and occurrence IDs are retained. Format projection includes an explicit mapping audit and is never used to reproduce the original SPDX field benchmark.

## Hypothesis & Experimental Design

The frozen numerical defaults are in `configs/agent-recovery-v1.json`: 100 distinct repositories, 20 development / 20 calibration / 60 test; release windows end at 2025-12-31, 2026-06-30 and 2026-10-28 16:59:59 UTC respectively. The last value is the end of 28 October in Asia/Ho_Chi_Minh.

Selection uses a frozen awesome-python snapshot, a verified public repository link in PyPI metadata, a compatible pure-Python root wheel up to 20 MiB, and fixed SHA-256 ranking. Actual build failures are retained. Replacements follow the same ranking and partition, excluding every previously attempted repository; no prediction score determines replacement. Large dependency closures above the declared 512 MiB compressed-wheel limit are excluded. This is a bounded population, not all of PyPI.

The actual installation and analysis happen after the historical horizon. `uv --exclude-newer` constrains artifact resolution; installation uses pinned hashes. Evidence acquisition time is distinct from its artifact-availability upper bound. The protocol is a retrospective reconstruction experiment, not proof that these targets were deployed then. Contemporary cohort selection creates survivorship bias. Provider model-training cutoffs are unknown; this does not establish pretraining-free chronological generalization.

Independent reference labels come from a fresh container, `pip inspect`, the installation report and `pip check`. `references` materializes full installed references from frozen inspection; application-closure references are also retained. The trusted Track 1 preparer reads these labels to construct and mask its input. Only the masked observation enters prediction. The full reference, removed-item log and label files never enter a prediction worker or seed external candidate acquisition.

Permitted evidence is declared before evaluation: observed native SBOMs, same-target scanner peers, top-level installed METADATA, and eligible static source declarations. Source files require a clean, tracked Git snapshot at or before the horizon; a release tag is not a build attestation. Dynamic build scripts and unsupported lockfile directives remain unknown. A complete target-metadata condition is an information-sufficient control: a deterministic extractor may already recover everything observable under these semantics.

Two evidence conditions are paired:

1. **Fixed**: identical frozen evidence is available to both deterministic and agent policies; acquisition is disabled.
2. **Active**: identical acquisition catalog, permissions and budgets (16, 64, 256). The deterministic policy uses fixed source-type/lexical priorities. Model generation has no overall token cap, but tool/turn/time bounds prevent infinite episodes.

Methods are observed-only, one globally selected scanner, pinned sbom-unifier, sbom-unifier followed by deterministic repair, deterministic repair alone, one agent, and Planner/Reconciler/Critic with the same model and verifier. The original unifier consumes SBOM peers; the enhanced deterministic controls also consume the metadata evidence available to the agents. An improvement over unifier alone cannot be attributed to AI when added evidence or verification explains it.

Every native-SBOM baseline receives all distinct scanner peers available to the agents, including the unmasked regeneration scan in controlled-mask cases. Exact duplicate documents are omitted, not new package occurrences. Installed Trivy scans use `rootfs`; source scans use `fs`. Original `fs`-mode installed snapshots and the associated development selection are retained as superseded engineering artifacts. The correction is based on the documented scanner scope, before any final calibration/test inference. SPDX package–file containment supplies occurrence locations for scope filtering; oracle membership never determines eligibility.

The automated allocation is frozen before held-out inference: the full primary budget-64 matrix has 13,320 cases, followed by a separate 2,880-case sensitivity subset at budgets 16/256 (raw plus 50% masks, seed 11). This subset does not support conclusions about unmeasured budget/rate combinations. The calibration matrix has 80 cases over all 20 calibration projects. The exact runner bytes and allocation are saved in the study plan.

**Track 1** constructs a native SPDX observation from the independently captured installed graph and known field labels, then applies component/metadata/dependency masks at rates 10/30/50/70%, seeds 11/23/42. The adapter preserves direct package edges and represents application roots with `DESCRIBES`, without synthetic dependency edges. The full reference is used only for trusted input generation and later scoring. Removal logs, input provenance and digests are saved outside worker mounts. Seals explicitly disclose pre-prediction reference use for masking; no claim is made that the host preparer is oracle-blind.

**Track 2** uses unmodified real generator discrepancies, with an installed-scope projection that records its mapping back to the immutable native capture. Source-file coverage uses full original source SBOMs. Raw discrepancies are not automatically MNAR. Development's additional corruption of scanner output is labeled `SCANNER_OUTPUT_MASK`; it is distinct from the primary independent-reference Track 1. Calibration and primary held-out masks use `INDEPENDENT_REFERENCE_MASK`. Controlled masks are MCAR stress tests and do not establish MNAR performance.

Development selects model/scanner globally; calibration and test require frozen selection. Pilot is restricted to development. Test labels never select a model. Three LLM repetitions are nested within project, not treated as new projects. Unsupported, timed-out and failed methods remain visible. Catastrophic inference failure retains the observed graph; a bounded or interrupted model episode can retain its last draft only after the same deterministic evidence gate checks it. Scoring failure never rewrites a sealed prediction. Model/tool limits are operational constraints, not a claim of unlimited per-response context or output.

The study controller and all prediction workers execute from an immutable source bundle in a fresh interpreter. A one-use inherited pipe transfers the API key, which is then held only in controller memory; it is absent from argv, exported environment, source bundles and worker mounts. Interrupted development can resume from its original bundle while later benchmark preparation evolves. Previously sealed predictions are reused; unfinished episode transcripts are archived, and any unreported in-flight usage remains unknown. Provider revisions and deterministic generation remain unverified when the gateway does not expose them.

The frozen `m25-agent-study-v2` uses the original non-streaming gateway adapter. The working-tree CLI later adds opt-in SSE for standalone `recover`/`preflight`; it is an engineering variant, not a replacement for recorded development outcomes or the primary study. Timeout and truncation failures remain explicit. Transport/response limits are a threat to interpreting measured implementation performance as an intrinsic model or algorithm capability.

## Empirical Evidence & Downstream Metrics

Measured facts belong in run artifacts, not this protocol. The original 90-project analyzer reproduction compares all four CSVs byte-for-byte. It measures completeness only. On new targets, record node/edge/field precision, recall and F1 for new changes and the whole graph, native schema/semantic validation, unsupported proposals, acquired evidence, tool calls, reported tokens, retries, elapsed time and unknown-cost fields.

Undefined denominators remain null. Unresolved reference requirements are not negatives. Bootstrap and paired randomization operate on project-level differences of matched cases, with 10,000 repetitions, 95% intervals and Holm correction. Shared dependencies and project selection limit the independence assumptions.

Optional project-group split conformal sets are fitted only on calibration decisions. The default calibration population is the deterministic gate's target-verified auto-apply proposals. Scores are rankings, not probabilities; calibration cannot bypass evidence checks. Missing calibration produces no calibrated-confidence claim. Temporal exchangeability is unverified, so no nominal coverage guarantee is asserted. Coverage versus selective risk is exported separately.

OSV snapshots are evaluation-only, timestamped and retrospective. VRR uses `(package PURL, advisory ID)` pairs reachable through independently confirmed direct edges; false shortcuts receive no credit, and root co-occurrence is excluded. Aliases are not presented as unique CVEs. Package paths never justify OpenVEX `affected` or `not_affected`. Triage delta and false-assurance reduction are unmeasured without independent product labels.

## Failure Taxonomy & Threats to Validity

Count node, direct-edge and known-metadata FP/FN under A namespace/PURL, B dynamic installation, C extras/markers, D registry ambiguity and E graph sparsity only when evidence supports attribution; keep the remainder UNRESOLVED. Error direction and unit are recorded separately from causal attribution. Report build, scan, model and validation failures separately.

Construct validity: installed declarations and field presence do not establish executable contents or exploitability. Internal validity: target metadata can make recovery trivial; oracle isolation alone does not demonstrate AI contribution. Source and installed scopes differ; conversion is not an interchangeable measurement. External validity: curated repositories, pure-Python roots, release availability, size limits, a single Linux/CPython profile and unknown LLM training contamination restrict generalization.

## Actionable Next Steps

Execute the CLI stages in `AGENT_RECOVERY.md`, preserve source bundles and run manifests, fit only on development/calibration, and report negative or equivalent results when supported. Full-matrix execution is distinct from implementing and smoke-testing the harness. No superiority claim is generated automatically.

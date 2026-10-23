# M2.3 validation protocol v1

This protocol implements the Human Researcher's conditional-approval directive. The thesis remains incomplete SBOM graph reconstruction. No ML training, agent experiment, or additional repository cohort is included in this milestone.

## Scope and labels

Normalization receives a generator document, a declared application root, and explicit bootstrap provisioning context. It never receives oracle membership. A versioned PyPI PURL is a distribution **candidate**; scanner paths distinguish files and vendored inventory. Unknown roles stay unknown. Bootstrap distributions remain in the normalized input. An application dependency on a bootstrap package is not forbidden.

Every source component, including a metadata root, has an audit row. All resolvable declared dependency edges are preserved. Absence of a dependency declaration is preserved as absence, not replaced by `dependsOn: []`. Raw files are copied byte-for-byte. Normalized/reconstructed CycloneDX 1.5 documents are checked against locally frozen official schemas, with additional reference-integrity checks.

The scorer alone reads independent installed-metadata labels. Outgoing edges from declared bootstrap distributions outside the reference application's closure are excluded from the application metric with an audit reason. Predicted application edges outside truth are false positives, including predictions to nodes absent from truth. Unresolved oracle requirements cannot provide negative labels. Whole-graph and incremental-addition metrics are separate; undefined denominators are null.

Scope is not runtime use. Package paths are Level 1 only. No path remains UNKNOWN. None of these results establishes static function reachability or exploitability.

## Public evidence and counterfactuals

Public acquisition seeds are the sorted exact distribution identities in normalized observed SBOMs. The bounded policy does not enumerate all registry releases and always declares PARTIAL_CANDIDATE_UNIVERSE. The legacy starting snapshot has a hard-coded collection cohort; its historical selection independence is not established retroactively.

Interventions: partial legacy snapshot; expanded compatible public wheel metadata; public evidence plus independently derived sdist metadata. Missing/incomplete metadata returns None, distinct from a verified empty list. Require artifact hashes, upload cutoff, Requires-Python and explicit target wheel tags. Unknown installation time uses a labeled conservative SBOM horizon and is never silently inferred from a parent release date.

For sdists inspect root PKG-INFO, advertised index Core Metadata, then an independent build backend. Older/dynamic source metadata is insufficient to claim completeness. Backend execution has no network, oracle or host source mount; 2 CPU, 2 GiB, 128 processes and 600-second limit. Record the source hash, extraction method, metadata hash, immutable image ID, preinstalled build tools, command and log. A generated wheel is evidence of that separate build, not the target installation.

Inference runs in a no-network Docker container containing only resolver/provider code, observed input, declared context and frozen evidence records. Oracle metadata is available only to the outer scorer. Each paired comparison freezes code, input, environment, oracle and snapshot hashes. Acquisition failures remain in query/build audit logs.

**Two tracks must remain separate:**

- Raw-generator discrepancy: preserve the actual Syft graph. The former normalizer erased existing edges; its reported zero-edge input is not a fact about the raw SBOMs.
- Controlled source masking: remove all dependency declarations from the normalized observed graph, retain component identities, and label the intervention CONTROLLED_SOURCE_MASKING. This recreates the historical ten-FN setting to test public-evidence repair; it is not an in-the-wild omission benchmark.

FP/FN attribution is generated from measured edge differences. The engineering taxonomy A–E and AI-feasibility categories A–D are distinct. A failure surviving a bounded acquisition budget is UNRESOLVED, not proof that permitted information cannot recover it.

## Information ablation

Keep PEP 508 expressions intact. Cross platform/Python knowledge (known versus a declared finite environment matrix) with requested-extra knowledge (known versus subsets of public Provides-Extra). Evaluate complete contexts, propagate child requested extras to a fixed point, and aggregate MUST/intersection and POSSIBLE/union. MUST is explicitly relative to the enumerated contexts, not all real environments. No numeric calibrated probability is claimed.

Use independent installations of requests==2.31.0 and requests[socks]==2.31.0. Their generator inputs are kept distinct from controlled source-masked versions used to expose information dependence. Platform combinations tested only as fixtures are labeled synthetic semantics tests.

## Reproduction and B4

Yu et al., *On the Correctness of Metadata-Based SBOM Generation: A Differential Analysis Approach*, IEEE/IFIP DSN 2024: <https://cs.ucr.edu/~heng/pubs/sbom-dsn24.pdf>. Benchmark commit e6bcf23b2f4e384f9fc398793529583845612b63, Python requirements entrypoints only: <https://github.com/DeepBitsTechnology/sbom-benchmark>.

This is a contemporary-tool partial reproduction, not the paper's full experiment. Author-supplied component/version labels and independently collected fresh installation labels are separate score regimes. No dependency-edge score is inferred from a component list. Artifact/installation failure is reported rather than silently modifying original inputs.

B4 is package-manager dry-run resolution with manifest/environment access: a privileged-information reference baseline. It is evaluated only against a separate installed-metadata capture, never its own report. A frozen candidate artifact set supports reproducible contemporary resolution but does not establish full-registry candidate completeness or historical installation identity.

## Primary specifications

- PyPA dependency/extras semantics: <https://packaging.python.org/en/latest/specifications/dependency-specifiers/>
- PyPA Core Metadata / Dynamic: <https://packaging.python.org/en/latest/specifications/core-metadata/>
- pip dry-run/report: <https://pip.pypa.io/en/stable/cli/pip_install/>
- CycloneDX 1.5 schema sources and hashes: `schemas/provenance.json`.

## Execution and artifact lifecycle

Install dependencies with `uv venv .venv` and `uv pip install --python .venv/bin/python -r requirements-research.txt`. Run `scripts/prepare_research.py` once to acquire pinned scanners, official schemas, paper and benchmark. Executable artifacts/download caches live in ignored `research/.work/`; source URLs and hashes are versioned. Docker is required for isolated execution.

Every new run requires a fresh output directory. The run manifest records source commit, input/output hashes, context, observed UTC stage times and completion/failure. Old SBOM timestamps remain in originals; new reconstructions get new serials and timestamps. Filesystem mtime/ctime is never used as original provenance. Retrospective runs with unavailable installation timing say UNKNOWN. Legacy reports remain unchanged and are not pooled with corrected measurements.

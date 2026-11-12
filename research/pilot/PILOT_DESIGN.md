# EAGER-SBOM Pilot Benchmark Design

**Date**: 2026-11-12  
**Goal**: Evaluate whether adaptive LLM-assisted evidence acquisition improves SBOM reconciliation beyond deterministic rule-based methods.

## Research Questions

**RQ-Pilot**: Does an LLM agent with adaptive evidence selection improve metadata correctness, dependency graph fidelity, and vulnerability triage accuracy compared to fixed-priority and rule-based reconciliation under equivalent evidence budgets?

## Pilot Scope

- **Repositories**: 20 (10 npm + 10 Cargo)
- **Conflict cases**: 200-400 natural + controlled
- **LLM configurations**: 2-3 models
- **Baseline methods**: 6 (B0-B5)
- **Evidence budget**: 5-10 tool calls per case

## Repository Selection Criteria

### Inclusion criteria
1. **Active maintenance**: commits within last 6 months
2. **Dependency complexity**: 15-100 direct+transitive dependencies
3. **Lockfile available**: npm package-lock.json v2/v3 or Cargo.lock
4. **Multi-tool discrepancies**: Syft/Trivy/CycloneDX generators show version or edge conflicts
5. **Known vulnerabilities**: at least 1 CVE in dependency tree (from frozen OSV snapshot)

### Exclusion criteria
- Monorepos with >5 package.json files
- Projects requiring proprietary build tools
- Dependencies with unresolvable private registries
- License restrictions on analysis/publication

## Baseline Methods

| ID | Method | Evidence Access | Planning |
|----|--------|----------------|----------|
| B0 | `sbom-unifier` | Input SBOMs only | Fixed merge |
| B1 | `deterministic` | Full evidence catalog | Fixed priority |
| B2 | `rule` | Full evidence catalog | Heuristic ranking |
| B3 | `llm-fixed` | Full evidence catalog | LLM reasoning, no tool calls |
| B4 | `llm-agent` | Evidence catalog via tools | Adaptive acquisition |
| B5 | `llm-explainer` | Full evidence catalog | LLM explains only, no decisions |

## Evidence Sources per Repository

Each repository bundle includes:

### Input SBOMs (immutable)
- Syft JSON output (v0.100+)
- Trivy CycloneDX 1.6
- npm/Cargo native SBOM (if generator available)
- GitHub Dependency Graph export (when applicable)

### Evidence Catalog (sealed, digest-checked)
- **Lockfile**: package-lock.json v3 or Cargo.lock
- **Native resolution**: `npm ls --all --json` or `cargo metadata --format-version 1`
- **Registry metadata**: frozen snapshots for all observed packages
- **Build manifest**: package.json / Cargo.toml with resolved features
- **Artifact inventory**: installed package list with hashes (when buildable)

### Oracle (evaluator-only, never exposed to methods)
- **Component identities**: verified name/version/PURL from clean install
- **Dependency edges**: verified direct dependencies with scope
- **Dependency paths**: verified transitive paths to root
- **Vulnerability labels**: package-level affected/not-affected from frozen OSV
- **Coverage metadata**: which domains are complete vs partial

## Conflict Types to Include

Target distribution across 20 repositories:

1. **Version conflicts** (40-60 cases): Two generators report different versions
2. **Identity ambiguity** (30-50 cases): Aliases, namespace variations, PURL mismatches
3. **Missing edges** (60-80 cases): One SBOM has edge, another doesn't
4. **Scope mismatches** (30-40 cases): dev vs runtime vs optional dependency differences
5. **Dangling references** (20-30 cases): Edge endpoint not found in component list

## Metrics

### Primary metrics (RQ-Pilot)
- **Component F1**: Precision/recall on verified component identities
- **Field accuracy**: Correct version, PURL, digest fields
- **Edge F1**: Precision/recall on verified dependency edges
- **Path recall**: Fraction of verified paths correctly reconstructed
- **Vulnerability F1**: Precision/recall on package-level CVE matches

### Agent-specific metrics
- **Evidence efficiency**: Conflicts resolved per tool call
- **Abstention quality**: Precision/recall on unknown declarations
- **Invalid action rate**: Tool calls rejected by validator
- **Cost per case**: Tokens, API calls, wall-clock time

### Trade-off analysis
- Accuracy vs budget curves
- Precision vs recall trade-offs
- Cost vs quality scatter plots

## Data Splits

- **Development**: 8 repositories (4 npm + 4 Cargo) — for prompt engineering and ablation
- **Test**: 12 repositories (6 npm + 6 Cargo) — held out, final evaluation only

No repository overlap between splits. Conflict cases from same repository stay in same split.

## LLM Configurations

### Models to evaluate
1. **GPT-4o** (OpenAI): Current SOTA baseline
2. **Claude Opus 5.5** (Anthropic): Strong reasoning, tool use
3. **Qwen 2.5 72B** (via Netmind gateway): Open model comparison

### Fixed parameters
- Temperature: 0 (deterministic)
- Seed: 11 (consistent across runs)
- Max output: 1024 tokens
- Timeout: 30s per call

## Oracle Construction Protocol

### Phase 1: Automated baseline (per repository)
1. Clean environment setup (Docker container)
2. Install from lockfile: `npm ci` or `cargo build --locked`
3. Capture installed inventory with hashes
4. Export native dependency tree
5. Run all SBOM generators with frozen versions
6. Hash all artifacts and evidence

### Phase 2: Conflict adjudication (per case)
1. Automated detector flags discrepancies
2. Human annotator reviews evidence
3. Two independent annotations for hard cases
4. Conflict resolution protocol with evidence citation
5. Final oracle labels include confidence and coverage

### Phase 3: Validation
- Cross-check: lockfile resolution vs installed packages
- Sanity: no component without evidence source
- Completeness: coverage flags for partial domains

## Budget Design

Equal-budget comparison for B1, B2, B4:

```json
{
  "max_tool_calls": 5,
  "max_model_calls": 10,
  "max_tokens": 32768,
  "max_cost_usd": 0.50,
  "max_seconds": 120.0
}
```

B0 (sbom-unifier) has no budget. B3 (llm-fixed) has model budget but no tool calls.

## Success Criteria

Pilot is successful if ANY of:
1. B4 achieves higher component F1 or edge F1 than B1/B2 with equal budget
2. B4 reaches equivalent accuracy with 30%+ fewer tool calls
3. B4 reduces false-negative vulnerability rate by 20%+ on CVE-focused subset

Pilot indicates further work needed if:
- B4 performs worse than B2 (rule-based) on any primary metric
- Invalid action rate >20%
- B3 (no tools) performs as well as B4 (with tools)

## Timeline

- **Week 1-2**: Repository selection and evidence collection
- **Week 3**: Oracle construction and adjudication
- **Week 4**: Baseline runs (B0, B1, B2)
- **Week 5**: LLM runs (B3, B4, B5)
- **Week 6**: Analysis and report

## Threats to Validity

### Internal validity
- **Data leakage**: Oracle must be sealed until after predictions
- **Evidence contamination**: B1-B5 must access same evidence catalog
- **Prompt engineering**: No test-set tuning; development-set prompt frozen before test

### External validity
- **Repository selection bias**: Limited to npm/Cargo with lockfiles
- **Conflict distribution**: May not reflect production SBOM disagreements
- **Model contamination**: Public repositories may be in training data

### Construct validity
- **Oracle correctness**: Manual adjudication may have errors
- **Metric alignment**: Package-level CVE ≠ exploitability
- **Budget realism**: Fixed budget may not reflect real workflows

## Deliverables

1. **Dataset**: 20 repository bundles with SBOMs, evidence, oracles (anonymized, MIT license)
2. **Code**: Pilot evaluation harness extending `sbom_recovery/investigation`
3. **Results**: Per-method metrics, statistical tests, ablation analysis
4. **Report**: Pilot findings with recommendations for full study

## Next Steps After Pilot

If pilot shows promise:
- Expand to 100-200 repositories
- Add Java/Maven ecosystem
- Multi-agent architectures
- Artifact-level reconciliation
- Real-world deployment case studies

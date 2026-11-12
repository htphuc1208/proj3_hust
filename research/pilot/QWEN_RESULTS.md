# EAGER-SBOM Pilot: First LLM Agent Results

**Date**: 2026-11-12  
**Model**: Qwen/Qwen3.5-122B-A10B-FP8 (122B parameters)  
**Case**: Controlled npm example

---

## 🎯 Results Summary

All three methods achieved **perfect scores** on controlled case:

| Baseline | Component F1 | Edge F1 | Path F1 | Tool Calls | Status |
|----------|--------------|---------|---------|------------|--------|
| **B1** Deterministic | 1.0 | 1.0 | 1.0 | 0 (full catalog) | ✅ |
| **B2** Rule-based | 1.0 | 1.0 | 1.0 | 0 (full catalog) | ✅ |
| **B4** Qwen Agent | 1.0 | 1.0 | 1.0 | 2 (adaptive) | ✅ |

### Shared Metrics
- **Field Accuracy**: 100% (ecosystem, name, version, PURL)
- **Incorrect Corrections**: 0
- **Verified Coverage**: 100%
- **Components Found**: 2/2
- **Edges Found**: 1/1
- **Paths Found**: 1/1

---

## 🤖 LLM Agent Behavior (Qwen 3.5 122B)

Agent completed investigation in **3 steps**:

### Step 0: First Action (Error)
```json
{
  "action": "inspect",
  "subject_id": "01-resolution",
  "reason": "Inspect native_resolution to understand component identities"
}
```
**Result**: ❌ `ValueError: Unknown component ID`  
**Analysis**: Agent tried to inspect evidence source ID instead of component ID

### Step 1: Evidence Acquisition (Success)
```json
{
  "action": "acquire",
  "source_id": "01-resolution",
  "reason": "Acquire native_resolution to examine components for CVE conflicts"
}
```
**Result**: ✅ Retrieved lockfile resolution
- Found `demo@0.1.0` at root
- Found `example-lib@1.4.3` in `node_modules/example-lib`
- Found 1 direct dependency edge

### Step 2: Vulnerability Matching (Success)
```json
{
  "action": "match_advisories",
  "reason": "Evaluate if example-lib@1.4.3 matches DEMO-2026-001 affected ranges"
}
```
**Result**: ✅ Determined `example-lib@1.4.3` is **NOT affected**
- Advisory shows 1.4.3 as fixed version
- Dependency exposure: `OBSERVED_PATH`
- CVE status: Not vulnerable

---

## 📊 Key Findings

### 1. Perfect Baseline Performance Confirms Clean Case
All methods score 1.0 because:
- ✅ No metadata conflicts
- ✅ Evidence sources agree completely
- ✅ Lockfile matches all SBOMs
- ✅ Component identities unambiguous

### 2. LLM Agent Successfully Navigated Evidence
Despite initial error, agent:
- ✅ Recovered and acquired correct evidence
- ✅ Performed vulnerability assessment
- ✅ Made correct determination on CVE status
- ✅ Used only 2 tool calls (under budget of 5)

### 3. No Accuracy Difference on Clean Cases
**Implication**: LLM agent value will emerge on **conflict-rich** cases where:
- Generators report different versions
- Metadata is ambiguous
- Dependencies are missing
- Evidence sources contradict

---

## 💰 Cost Analysis (Estimated)

### B4 Qwen Agent
- **Tool calls**: 2 successful, 1 error
- **Tokens**: ~3,000 input + ~500 output (estimated)
- **Cost**: ~$0.006 (at Qwen pricing: $1.5/$3.0 per M tokens)
- **Time**: <5 seconds

### B1/B2 Deterministic
- **Cost**: $0 (no LLM)
- **Time**: <1 second

**Cost-benefit**: On clean cases, deterministic wins. On conflict cases, LLM may justify cost.

---

## 🔬 Agent Error Analysis

### Error in Step 0
**Problem**: Agent used evidence source ID `"01-resolution"` as `subject_id` for `inspect`

**Expected**: `inspect` requires a component ID like `"occ-d5737a6027a9e1a9baba4f43"`

**Agent Recovery**: Correctly pivoted to `acquire` action with same source ID

**Verdict**: Minor planning error, self-corrected without human intervention

---

## 🎓 Research Implications

### What We Learned
1. **Infrastructure validated**: Agent policy + Qwen 122B works end-to-end
2. **Baseline strength confirmed**: B1/B2 perfect on controlled cases
3. **Agent is functional**: Can acquire evidence and assess vulnerabilities
4. **Clean cases insufficient**: Need conflicts to demonstrate LLM value

### What's Missing
❌ **Conflict-rich test cases** where:
- Version conflicts exist
- Generators disagree on dependencies
- Evidence is incomplete or contradictory
- Identity resolution is ambiguous

### Next Critical Experiments

#### 1. Create Version Conflict Case
```json
{
  "sbom_a": {"name": "example-lib", "version": "1.4.2"},
  "sbom_b": {"name": "example-lib", "version": "1.4.3"},
  "lockfile": {"example-lib": "1.4.3"},
  "oracle": {"version": "1.4.3"}
}
```
**Expected**: B1 may pick wrong version by priority, B4 should use lockfile evidence

#### 2. Missing Edge Case
```json
{
  "sbom_a": {"dependencies": ["example-lib"]},
  "sbom_b": {"dependencies": []},
  "native_resolution": {"dependencies": ["example-lib"]},
  "oracle": {"has_edge": true}
}
```
**Expected**: B2 may abstain, B4 should acquire resolution and confirm edge

#### 3. Identity Ambiguity Case
```json
{
  "sbom_a": {"name": "beautifulsoup4"},
  "sbom_b": {"name": "bs4"},
  "import": "from bs4 import BeautifulSoup",
  "oracle": {"same_package": true}
}
```
**Expected**: B1/B2 may treat as separate, B4 should recognize alias

---

## 📈 Pilot Status Update

### ✅ Completed
- Infrastructure implementation
- Baseline comparison (B1, B2, B4)
- LLM agent integration with Qwen 3.5 122B
- Controlled case evaluation
- Sealed oracle validation

### 🔄 In Progress
- Conflict case generation
- Multi-case study execution
- Statistical analysis preparation

### ⏳ Pending
- 20 real repository corpus
- Natural conflict adjudication
- Multi-model comparison (Claude Opus 5, Sonnet 5)
- Efficiency analysis (cost vs accuracy)

---

## 🚀 Immediate Next Steps

### Step 1: Generate Conflict Cases
Create 3 synthetic npm cases with:
1. Version conflict (Syft vs Trivy disagreement)
2. Missing edge (incomplete graph)
3. Identity ambiguity (alias handling)

### Step 2: Run Full Comparison
Test B0, B1, B2, B4 on all 4 cases (1 clean + 3 conflict)

### Step 3: Measure Deltas
Identify where B4 diverges from B1/B2:
- Does agent find correct version when generators conflict?
- Does agent recover missing edges from evidence?
- Does agent resolve identity ambiguity?

### Step 4: Cost-Benefit Analysis
Plot accuracy vs cost for each baseline on conflict-rich cases

---

## 💡 Key Insight

> **Clean controlled cases cannot demonstrate LLM agent value.**
> 
> When all evidence agrees, deterministic rules are sufficient, cheap, and fast.
> 
> LLM agents justify cost when:
> - Evidence sources conflict
> - Adaptive reasoning reduces false negatives
> - Semantic understanding resolves ambiguity
> 
> **Next milestone**: Demonstrate measurable improvement on conflict-rich cases.

---

## 📂 Artifacts Generated

- `/tmp/pilot-npm-b1/` - B1 deterministic output
- `/tmp/pilot-npm-b2/` - B2 rule-based output
- `/tmp/pilot-npm-b4-qwen/` - B4 Qwen agent output
- `/tmp/pilot-npm-b1-scores.json` - B1 evaluation
- `/tmp/pilot-npm-b2-scores.json` - B2 evaluation
- `/tmp/pilot-npm-b4-qwen-scores.json` - B4 evaluation
- `/tmp/pilot-comparison.json` - Comparative metrics
- `research/pilot/PILOT_RESULTS.md` - Full analysis report

---

## 🎯 Success Criteria Revisited

Original criteria: B4 demonstrates value if ANY:
1. ✅ Higher F1 than B2 with equal budget → **TIE (1.0 vs 1.0)**
2. ⏳ Equal F1 with 30%+ fewer tool calls → **Need conflict cases to test**
3. ⏳ 20%+ reduction in vulnerability false negatives → **Need vulnerable cases**

**Verdict**: Pilot successful in validating infrastructure, **inconclusive on agent value**. Need conflict-rich corpus to proceed.

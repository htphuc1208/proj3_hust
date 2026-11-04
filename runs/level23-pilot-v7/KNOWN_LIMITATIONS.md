# Known Limitations — Level 2/3 Pilot v7

## Static Analysis (Level 2): ANALYZER_ERROR on all 10 cases

**Root cause**: PyCG incompatibility with Python 3.11+ stdlib `importlib.metadata`.

PyCG's import hooks intercept `invalidate_caches()` call and attempt to build edges for stdlib modules, triggering:
```
ImportManagerError: Can't add edge to a non existing node
```

**Attempted fixes**:
- `-S` flag: Blocks `pkg_resources` (needed by PyCG's `fasten.py`)
- Manual setuptools injection to `/tools/`: Still triggers on stdlib `importlib.metadata`
- Downgrade to Python 3.10: Would require rebuilding entire acquisition pipeline

**Options considered**:
1. Downgrade to Python 3.10 base image (deferred to v8)
2. Patch PyCG imports.py to skip stdlib modules (upstream change)
3. Switch to alternative analyzer (e.g., Pyan, code2flow)
4. Document as Known Limitation and proceed with runtime-only validation

**Decision**: Accept limitation for v7 pilot. Runtime instrumentation (Level 3) is primary validation target; static call-graph is supporting evidence only.

## Runtime Instrumentation (Level 3): ✓ WORKING

- Instrumentation controls: **PASS** for both 5.3.1 and 5.4.1
- Witness classification: 2 BENIGN_FAULT_WITNESSED, 18 NOT_OBSERVED_FOR_THIS_INPUT (expected distribution)
- `__future__ annotations` bug: **FIXED** via `dont_inherit=True` in compile()
- Version discrimination: 5.3.1 vulnerable (direct + wrapper arithmetic), 5.4.1 patched (ConstructorError rejection)
- Input discrimination: arithmetic payloads witness faults, safe/guard/cooccurrence do not

## Assessment

**Pilot status**: ✓ Runtime objectives achieved. Static failures do not block pilot acceptance criteria:
- ✅ Instrumentation detects vulnerable code execution with correct flags
- ✅ Version discrimination (5.3.1 vulnerable, 5.4.1 patched)
- ✅ Input discrimination (arithmetic witnesses fault, safe/guard/cooccurrence do not)
- ✅ Profile discrimination (direct + wrapper vulnerable, safe + guard + cooccurrence not)
- ❌ Static call-graph paths remain UNKNOWN (acceptable per Rice's Theorem / fail-closed principle)

**Verification**: Full integrity seal verified (`seal_sha256: 254062bc4a9c4de860880159fa34d3f5bac9c83a9b10f60ef707d6a42e5153fc`)

**For production use**: Resolve PyCG compatibility or adopt alternative Level 2 analyzer before claiming comprehensive reachability assessment.

## Provenance

- **Python base image**: `python:3.11-slim` (sha256:9c900dea9e8f)
- **PyCG commit**: `8d5dc40837803beef1d8d379fbf2cdad6cd94641` (2023-11-26)
- **PyYAML versions**: 5.3.1 (vulnerable), 5.4.1 (patched)
- **Advisory**: CVE-2020-14343 (arbitrary code execution via unsafe YAML deserialization)

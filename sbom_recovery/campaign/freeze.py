"""Snapshot exact source bytes so a dirty working tree is still reviewable and reproducible."""
from pathlib import Path
import shutil

from sbom_recovery.core.research_core import digest, load
from sbom_recovery.core.formats import sha
from sbom_recovery.evidence.storage import save

def _find_repo_root() -> Path:
    p = Path(__file__).resolve()
    for parent in p.parents:
        if (parent / '.git').exists() or (parent / 'pyproject.toml').exists():
            return parent
    return p.parents[2]

ROOT = _find_repo_root()


def source_files():
    return sorted(sorted(list((ROOT / "sbom_recovery").glob("**/*.py"))) +
                  [ROOT / n for n in ("research_core.py", "resolver.py", "registry_provider.py", "graph_triage.py", "benchmark.py",
                                     "container_runner.py", "controlled_reference.py", "requirements-agent.txt", "pyproject.toml",
                                     "scripts/run_agent_study.py", "research/AGENT_PROTOCOL.md", "configs/agent-recovery-v1.json")] +
                  list((ROOT / "research/schemas").glob("*.schema.json")))


def source_fingerprint():
    return {str(p.relative_to(ROOT)): digest(p) for p in source_files()}


def freeze(destination):
    destination = Path(destination)
    files = source_fingerprint()
    if (destination / "source_manifest.json").exists():
        if load(destination / "source_manifest.json")["files"] != files:
            raise ValueError("Campaign source changed; use another run directory")
        return sha(files)
    destination.mkdir(parents=True, exist_ok=True)
    for name in files:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    save(destination / "source_manifest.json", {"files": files, "sha256": sha(files)})
    return sha(files)

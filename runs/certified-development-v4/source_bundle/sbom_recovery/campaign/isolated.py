"""Mount-enforced prediction/oracle separation; model traffic stays in the controller."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import tempfile
import uuid

from sbom_recovery.core.research_core import digest, load, save
from sbom_recovery.evidence.evidence import EvidenceStore
from sbom_recovery.core.formats import sha
from sbom_recovery.evidence.storage import save

def _find_repo_root() -> Path:
    p = Path(__file__).resolve()
    for parent in p.parents:
        if (parent / '.git').exists() or (parent / 'pyproject.toml').exists():
            return parent
    return p.parents[2]

ROOT = _find_repo_root()


def build_worker_image():
    work = ROOT / "research/.work/agent-worker-image"
    work.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "requirements-agent.txt", work / "requirements.txt")
    (work / "Dockerfile").write_text("FROM python:3.13.5-slim\nRUN pip install --no-cache-dir -r /requirements.txt\n".replace(
        "RUN pip", "COPY requirements.txt /requirements.txt\nRUN pip"))
    result = subprocess.run(["docker", "build", "-t", "sbom-recovery-worker:v1", str(work)], capture_output=True, text=True)
    (work / "build.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError("Worker image build failed; see " + str(work / "build.log"))
    image = subprocess.check_output(["docker", "image", "inspect", "sbom-recovery-worker:v1", "--format", "{{.Id}}"], text=True).strip()
    save(work / "image.json", {"image": image, "requirements_sha256": digest(ROOT / "requirements-agent.txt")})
    return image


class IsolatedBroker:
    def __init__(self, document, store, context, budget=64, sources=None, active=False, image=None, calibration=None):
        self.document, self.context, self.budget = deepcopy(document), context, budget
        self.host_store = store
        self.trace, self.active = [], active
        self.scratch = tempfile.TemporaryDirectory(prefix="sbom-agent-blind-")
        root = Path(self.scratch.name)
        code, inputs, evidence, artifacts = [root / n for n in ("code", "input", "evidence", "artifacts")]
        for p in (code, inputs, artifacts):
            p.mkdir()
        shutil.copytree(ROOT / "sbom_recovery", code / "sbom_recovery", ignore=shutil.ignore_patterns("__pycache__"))
        for name in ("research_core.py", "resolver.py", "registry_provider.py", "graph_triage.py"):
            shutil.copyfile(ROOT / name, code / name)
        shutil.copytree(ROOT / "research/schemas", code / "research/schemas")
        store.export(evidence)
        self.worker_evidence = evidence
        bound_sources = deepcopy(sources or {})
        for key, source in bound_sources.items():
            if source["kind"] in {"target_metadata", "source_file"}:
                target = artifacts / key
                shutil.copyfile(source["path"], target)
                source["path"] = "/artifacts/" + key
        save(inputs / "config.json", {"document": document, "context": context.model_dump() if context else None,
             "budget": budget, "active": active, "sources": bound_sources, "calibration": calibration})
        self.name = "sbom-agent-" + uuid.uuid4().hex
        if image is None:
            image = load(ROOT / "research/.work/agent-worker-image/image.json")["image"]
        args = ["docker", "run", "--rm", "-i", "--name", self.name, "--cap-drop=ALL", "--security-opt=no-new-privileges",
                "--read-only", "--memory=1g", "--cpus=1", "--pids-limit=64", "--user", f"{os.getuid()}:{os.getgid()}",
                "--tmpfs", "/tmp:rw,size=128m", "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "PYTHONPATH=/code",
                "-v", f"{code}:/code:ro", "-v", f"{inputs}:/input:ro", "-v", f"{artifacts}:/artifacts:ro",
                "-v", f"{evidence}:/evidence:rw", "--entrypoint", "python", image, "-m", "sbom_recovery.worker"]
        if not active:
            args[2:2] = ["--network", "none"]
        self.process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.audit = {"command": args, "image": image, "oracle_mounted": False, "key_in_worker": False,
                      "network": "registry-broker-only" if active else "none",
                      "initial_evidence_sha256": sha(store.manifest()),
                      "input_sha256": digest(inputs / "config.json"),
                      "code_sha256": {str(p.relative_to(code)): digest(p) for p in code.rglob("*.py")}}

    def _rpc(self, request):
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        selector = selectors.DefaultSelector()
        selector.register(self.process.stdout, selectors.EVENT_READ)
        ready = selector.select(timeout=120)
        selector.close()
        if not ready:
            raise ValueError("WORKER_RPC_TIMEOUT")
        line = self.process.stdout.readline()
        if not line:
            raise ValueError("WORKER_EXITED: " + self.process.stderr.read()[:1000])
        response = json.loads(line)
        self.trace = response["trace"]
        if not response["ok"]:
            raise ValueError(response["error"])
        return response["result"]

    def call(self, name, arguments, proposals=None):
        return self._rpc({"kind": "tool", "name": name, "arguments": arguments, "proposals": proposals})

    def finalize(self, proposals):
        return self._rpc({"kind": "finalize", "proposals": proposals})

    def deterministic(self):
        return self._rpc({"kind": "deterministic"})

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.terminate()
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True, timeout=15)
        copied = EvidenceStore(self.worker_evidence)
        try:
            for payload in copied.manifest()["records"]:
                _, raw = copied.read(payload["evidence_id"])
                self.host_store.import_record(payload, raw)
            self.audit["final_evidence_sha256"] = sha(self.host_store.manifest())
        finally:
            copied.close()
            self.scratch.cleanup()

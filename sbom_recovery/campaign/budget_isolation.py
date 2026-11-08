"""Controller-owned source reader with a network-disabled prediction worker."""
import base64
import json
import os
from pathlib import Path
import selectors
import subprocess
import time
import uuid

from sbom_recovery.core.research_core import load, digest
from sbom_recovery.core.formats import sha
from .freeze import freeze
from sbom_recovery.evidence.storage import save

def _find_repo_root() -> Path:
    p = Path(__file__).resolve()
    for parent in p.parents:
        if (parent / '.git').exists() or (parent / 'pyproject.toml').exists():
            return parent
    return p.parents[2]

ROOT = _find_repo_root()


class BudgetIsolatedBroker:
    def __init__(self, document, context, catalog, reader, out, *, budget=4, byte_budget=2097152,
                 max_tools=128, max_source_bytes=262144, code=None, image=None):
        self.out = Path(out).resolve()
        self.out.mkdir(parents=True, exist_ok=False)
        self.reader = reader
        self.budget, self.source_requests = budget, 0
        self.source_sizes = {s['source_id']:s['bytes'] for s in catalog['sources']}
        self.unrestricted = budget is None
        self.name = "sbom-budget-" + uuid.uuid4().hex
        if code is None:
            code = self.out / "source_bundle"
            freeze(code)
        code = Path(code).resolve()
        config = {"document": document, "context": context.model_dump(), "catalog": catalog,
                  "budget": budget, "byte_budget": byte_budget, "max_tools": max_tools,
                  'max_source_bytes':max_source_bytes}
        inputs, outputs = self.out / "input", self.out / "worker"
        inputs.mkdir(); outputs.mkdir()
        save(inputs / "config.json", config)
        image = image or load(ROOT / "research/.work/agent-worker-image/image.json")["image"]
        limits = [] if self.unrestricted else ['--memory=1g','--cpus=1','--pids-limit=64']
        command = ["docker", "run", "--rm", "-i", "--name", self.name, "--network", "none", "--read-only",
                   "--cap-drop=ALL", "--security-opt=no-new-privileges", *limits,
                   "--user", f"{os.getuid()}:{os.getgid()}", "--tmpfs", "/tmp:rw" if self.unrestricted else "/tmp:rw,size=64m",
                   "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "PYTHONPATH=/code",
                   "-v", f"{code}:/code:ro", "-v", f"{inputs}:/input:ro", "-v", f"{outputs}:/out:rw",
                   "--entrypoint", "python", image, "-m", "sbom_recovery.budget_worker"]
        self.audit = {"command": command, "image": image, "network": "none", "oracle_mounted": False,
                      "target_mounted": False, "credentials_in_worker": False,
                      "input_sha256": digest(inputs / "config.json"), "catalog_sha256": catalog["sha256"],
                      "source_manifest_sha256": digest(code / "source_manifest.json")}
        save(self.out / "worker-boundary.json", self.audit)
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, bufsize=1)
        self.runtime_checked = False

    def _verify_runtime(self):
        if self.runtime_checked:
            return
        info = json.loads(subprocess.check_output(["docker", "inspect", self.name], text=True))[0]
        mounts = {m["Destination"]: {"source":m["Source"],"rw":m["RW"]} for m in info["Mounts"]}
        names = [v.split("=",1)[0] for v in info["Config"].get("Env",[])]
        checked = {"mounts":mounts,"environment_variable_names":names,
                   "network":info["HostConfig"]["NetworkMode"],"read_only_root":info["HostConfig"]["ReadonlyRootfs"],
                   'memory_limit':info['HostConfig']['Memory'],'cpu_limit':info['HostConfig']['NanoCpus'],
                   'pids_limit':info['HostConfig'].get('PidsLimit'),
                   "image":info["Image"],"target_mounted":False,"oracle_mounted":False}
        if (set(mounts) - {"/code","/input","/out","/tmp"} or mounts["/code"]["rw"]
                or mounts["/input"]["rw"] or "NETMIND_API_KEY" in names or checked["network"]!="none"
                or not checked["read_only_root"]):
            raise ValueError("Runtime isolation contract failed")
        if self.unrestricted and (checked['memory_limit'] or checked['cpu_limit'] or checked['pids_limit'] not in (None,0,-1)):
            raise ValueError('Unexpected resource cap in unrestricted worker')
        save(self.out / "runtime-boundary.json",checked)
        self.runtime_checked = True

    def _send(self, value):
        self.process.stdin.write(json.dumps(value) + "\n")
        self.process.stdin.flush()

    def _rpc(self, request):
        self._send(request)
        deadline = None if self.unrestricted else time.monotonic() + 120
        while True:
            selector = selectors.DefaultSelector()
            selector.register(self.process.stdout, selectors.EVENT_READ)
            ready = selector.select(timeout=60 if deadline is None else min(60, max(0, deadline - time.monotonic())))
            selector.close()
            if not ready:
                if deadline is None or time.monotonic() < deadline:
                    continue
                raise TimeoutError("Budget worker RPC deadline")
            line = self.process.stdout.readline()
            if not line:
                raise RuntimeError("Budget worker exited: " + str(self.process.poll()))
            reply = json.loads(line)
            if reply.get("kind") == "source_request":
                self.source_requests += 1
                source_id, limit = reply.get("source_id"), reply.get("limit")
                try:
                    if ((self.budget is not None and self.source_requests > self.budget)
                            or type(limit) is not int or not 0 <= limit <= self.source_sizes.get(source_id, -1)):
                        raise ValueError("Source RPC exceeded controller budget")
                    raw = self.reader(source_id, limit)
                    value = {"kind": "source_reply", "source_id": source_id, "ok": True,
                             "base64": base64.b64encode(raw).decode()}
                except (ValueError, KeyError, OSError):
                    value = {"kind": "source_reply", "source_id": source_id, "ok": False}
                self._send(value)
                continue
            if reply.get("kind") != "result" or not reply.get("ok"):
                raise ValueError("Worker rejected tool call: " + str(reply.get("error_type")))
            self._verify_runtime()
            return reply["result"]

    def call(self, name, arguments):
        return self._rpc({"kind": "call", "name": name, "arguments": arguments})

    def finalize(self):
        return self._rpc({"kind": "finalize"})

    def close(self):
        if self.process.poll() is None:
            try:
                self._send({"kind": "close"})
                self.process.stdin.close()
                self.process.wait(timeout=5)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                subprocess.run(["docker", "rm", "-f", self.name], capture_output=True, timeout=20)
                self.process.wait(timeout=10)
        save(self.out / "reader-audit.json", {"source_requests": self.source_requests,
             "acquisition_budget": self.budget, "target_mounted": False, "source_contents_available_only_after_rpc": True})

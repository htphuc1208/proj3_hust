"""Exercise the real frozen-controller boundary without making an API call."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from scripts.run_agent_study import ROOT, launch_frozen, stage_specs


class StudyRunnerTests(unittest.TestCase):
    def test_registered_case_counts(self):
        stages=stage_specs()
        self.assertEqual(sum(s["expected_cases"] for s in stages if s["name"] in {"test/raw","test/controlled"}),13320)
        self.assertTrue(all(s["mask_origin"]=="reference" for s in stages))

    @unittest.skipUnless(Path("/proc").exists(),"Linux process boundary check")
    def test_detached_controller_uses_frozen_code_and_does_not_persist_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            out=Path(temp)/"study"
            secret="SBOM_TEST_GATEWAY_SECRET_NEVER_PERSIST_9382"
            args=argparse.Namespace(out=str(out),cohort=str(ROOT/"runs/m25-cohort-buildable-v4/cohort.json"),
                captures=str(ROOT/"research/.work/m25-cohort-captures-v2"),
                snapshot=str(ROOT/"runs/m25-osv-snapshot-v1/snapshot.json"),
                development_runs=[str(Path(temp)/"not-started")],workers=2,background=True)
            with patch.dict(os.environ,{"NETMIND_API_KEY":secret}):
                launched,process=launch_frozen(args,secret)
            pid=launched["controller_pid"]
            try:
                deadline=time.monotonic()+15
                state=None
                while time.monotonic()<deadline:
                    try:
                        state=json.loads((out/"state.json").read_text())
                    except (FileNotFoundError,json.JSONDecodeError):
                        time.sleep(.05);continue
                    if state.get("status")=="WAITING_DEVELOPMENT":break
                    time.sleep(.05)
                self.assertIsNotNone(state,(out/"controller.log").read_text())
                self.assertEqual(state["status"],"WAITING_DEVELOPMENT")
                command=Path(f"/proc/{pid}/cmdline").read_bytes()
                environment=Path(f"/proc/{pid}/environ").read_bytes()
                self.assertIn(str(out/"source_bundle/scripts/run_agent_study.py").encode(),command)
                self.assertNotIn(secret.encode(),command)
                self.assertNotIn(secret.encode(),environment)
                for path in out.rglob("*"):
                    if path.is_file() and "research/.work" not in str(path):
                        self.assertNotIn(secret.encode(),path.read_bytes(),str(path))
            finally:
                try:os.kill(pid,signal.SIGINT)
                except ProcessLookupError:pass
                try:process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill();process.wait(timeout=5)


if __name__=="__main__":
    unittest.main()

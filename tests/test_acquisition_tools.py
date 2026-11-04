"""Unit tests for Evidence Acquisition Tools and Schedulers (Experiment E2)."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sbom_recovery.acquisition_tools import (
    AgentPlanner,
    BudgetedScheduler,
    DeterministicSchedulers,
    EvidenceToolCatalog,
)


class TestAcquisitionTools(unittest.TestCase):
    def test_budget_exhaustion(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir)
            (p / "uv.lock").write_text("lockfile content", encoding="utf-8")
            (p / "pyproject.toml").write_text("manifest content", encoding="utf-8")

            catalog = EvidenceToolCatalog(target_dir=p)
            scheduler = BudgetedScheduler(catalog=catalog, max_actions=1)

            res1 = scheduler.execute_action("read_lockfile", lockfile_name="uv.lock")
            self.assertIn("content", res1)
            self.assertEqual(scheduler.actions_used, 1)

            # Second action should fail budget check
            res2 = scheduler.execute_action("inspect_manifest", manifest_file="pyproject.toml")
            self.assertIn("error", res2)
            self.assertEqual(res2["error"], "Budget exhausted")

    def test_d1_fixed_order(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir)
            (p / "uv.lock").write_text("lock content", encoding="utf-8")
            (p / "pyproject.toml").write_text("manifest content", encoding="utf-8")

            catalog = EvidenceToolCatalog(target_dir=p)
            scheduler = BudgetedScheduler(catalog=catalog, max_actions=2)

            history = DeterministicSchedulers.run_d1_fixed_order(
                scheduler=scheduler,
                manifest_files=["pyproject.toml"],
                lockfiles=["uv.lock"],
            )

            self.assertEqual(len(history), 2)
            self.assertEqual(history[0].tool_name, "read_lockfile")
            self.assertEqual(history[1].tool_name, "inspect_manifest")

    def test_d2_greedy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir)
            (p / "requests.lock").write_text("requests lock", encoding="utf-8")
            (p / "random.txt").write_text("random", encoding="utf-8")

            catalog = EvidenceToolCatalog(target_dir=p)
            scheduler = BudgetedScheduler(catalog=catalog, max_actions=1)

            conflicts = [("pkg:pypi/requests@2.31.0", "version")]
            history = DeterministicSchedulers.run_d2_greedy(
                scheduler=scheduler,
                unresolved_conflicts=conflicts,
                available_files=["random.txt", "requests.lock"],
            )

            self.assertEqual(len(history), 1)
            # Greedy should pick requests.lock first
            self.assertEqual(history[0].arguments["lockfile_name"], "requests.lock")

    def test_a2_planner(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir)
            (p / "uv.lock").write_text("root lock content", encoding="utf-8")
            (p / "pyproject.toml").write_text("root manifest content", encoding="utf-8")
            (p / "urllib3.METADATA").write_text("urllib3 metadata", encoding="utf-8")

            catalog = EvidenceToolCatalog(target_dir=p)
            scheduler = BudgetedScheduler(catalog=catalog, max_actions=2)

            conflicts = [("pkg:pypi/urllib3@2.0.0", "version")]
            history = AgentPlanner.run_a2_planner(
                scheduler=scheduler,
                unresolved_conflicts=conflicts,
                available_files=["pyproject.toml", "urllib3.METADATA", "uv.lock"],
            )

            self.assertEqual(len(history), 2)
            self.assertEqual(history[0].tool_name, "read_lockfile")
            self.assertEqual(history[1].tool_name, "inspect_manifest")


if __name__ == "__main__":
    unittest.main()

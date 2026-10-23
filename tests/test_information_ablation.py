import unittest

from information_ablation import context_ablation
from resolver import DependencyRequirement, TargetEnvironment
from scripts.generate_fn_root_cause_report import measured_failures
from research_core import ROOT, load


class Provider:
    source_name = "SYNTHETIC_SEMANTICS_TEST"
    def get_requirements(self, purl):
        return {"pkg:pypi/app@1": [DependencyRequirement("pkg:pypi/platform@1", marker='sys_platform == "win32"'),
                                  DependencyRequirement("pkg:pypi/optional@1", marker='extra == "feature"'),
                                  DependencyRequirement("pkg:pypi/mixed@1", marker='(sys_platform == "win32" and extra == "feature") or python_version < "3.11"')]}.get(purl)


class TestInformationAblation(unittest.TestCase):
    def test_information_loss_changes_modalities_without_rewriting_markers(self):
        sbom = {"metadata": {"component": {"name": "app", "purl": "pkg:pypi/app@1", "bom-ref": "app", "version": "1"}}}
        env = TargetEnvironment("posix", "linux", "x86_64", "3.11", active_extras={"feature"})
        results = context_ablation(sbom, Provider(), env, {"feature"})
        key = lambda rows: {tuple(r) for r in rows}
        optional = ("pkg:pypi/app@1", "pkg:pypi/optional@1")
        platform = ("pkg:pypi/app@1", "pkg:pypi/platform@1")
        self.assertIn(optional, key(results['E1X1']['must']))
        self.assertNotIn(optional, key(results['E1X0']['must']))
        self.assertIn(optional, key(results['E1X0']['may_only']))
        self.assertNotIn(platform, key(results['E1X1']['possible']))
        self.assertIn(platform, key(results['E0X1']['may_only']))
        self.assertTrue(key(results['E1X1']['possible']) <= key(results['E0X0']['possible']))

    def test_repaired_edges_are_derived_from_measured_interventions(self):
        path = ROOT / 'runs/m23-controlled-repair-v2/counterfactual_evidence_repair.json'
        if not path.exists():
            self.skipTest('Run the controlled repair integration experiment first')
        report = load(path)
        rows = measured_failures(path)
        for row in rows:
            project = next(p for p in report['projects'] if p['project'] == row['project'])
            edge = [row['source'], row['target']]
            before = project['regimes']['partial']['baselines']['B3']['missed_edges']
            after = project['regimes']['sdist']['baselines']['B3']['missed_edges']
            self.assertIn(edge, before)
            self.assertEqual(row['recovered'], edge not in after)
            if row['recovered']:
                self.assertEqual(row['feasibility_category'], 'B')

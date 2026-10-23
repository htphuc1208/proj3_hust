import copy
import unittest

from research_baselines import b4_from_report
from research_core import ROOT, load, score_sets
from scripts.run_paper_reproduction import author_labels


class TestB4(unittest.TestCase):
    def test_dry_run_prediction_uses_only_report_and_public_roots(self):
        report = {'environment': {'sys_platform': 'linux', 'python_version': '3.11'}, 'install': [
            {'metadata': {'name': 'app', 'version': '1', 'requires_dist': ['dep[feature]>=2']}},
            {'metadata': {'name': 'dep', 'version': '2', 'requires_dist': ['extra==3; extra == "feature"']}},
            {'metadata': {'name': 'extra', 'version': '3'}}]}
        original = copy.deepcopy(report)
        result = b4_from_report(report, ['app==1'])
        self.assertEqual(report, original)
        self.assertEqual(result['predicted_edges'], [('pkg:pypi/app@1', 'pkg:pypi/dep@2'), ('pkg:pypi/dep@2', 'pkg:pypi/extra@3')])
        self.assertEqual(result['unresolved'], [])
        self.assertIn('PRIVILEGED', result['information_budget'])

    def test_absent_resolved_requirement_remains_unresolved(self):
        result = b4_from_report({'environment': {}, 'install': [{'metadata': {'name': 'app', 'version': '1', 'requires_dist': ['missing>=1']}}]}, ['app'])
        self.assertEqual(result['predicted_edges'], [])
        self.assertEqual(len(result['unresolved']), 1)

    def test_undefined_precision_is_not_reported_as_perfect(self):
        result = score_sets({'x'}, set())
        self.assertIsNone(result['precision'])
        self.assertEqual(result['recall'], 0)

    def test_published_labels_are_component_labels_with_url_versions(self):
        source = ROOT / 'research/.work/sbom-benchmark/python/req/groundtruth'
        if not source.exists():
            self.skipTest('Requires the pinned public benchmark checkout')
        identities, unresolved = author_labels(source)
        self.assertIn('pkg:pypi/fastapi@0.111.0', identities)
        self.assertIn('pkg:pypi/urllib3@1.26.8', identities)
        self.assertEqual(unresolved, [])

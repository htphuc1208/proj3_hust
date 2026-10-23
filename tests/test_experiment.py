import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiment import extract, score, prf
from poc import read_json


class EvaluationTests(unittest.TestCase):
    def test_full_fixture_has_expected_structure(self):
        truth = read_json(ROOT / 'fixtures/full_synthetic.cdx.json')
        n, e, dangling = extract(truth)
        self.assertEqual(len(n), 4)
        self.assertEqual(len(e), 3)
        self.assertEqual(dangling, 0)

    def test_evaluation_counts_only_new_recovered_edges(self):
        gold = {('a', 'b'), ('b', 'c')}
        observed = {('a', 'b')}
        predicted = {('a', 'b'), ('b', 'c'), ('a', 'c')}
        metrics = score(gold, observed, predicted)
        self.assertEqual((metrics['tp'], metrics['fp'], metrics['fn']), (1, 1, 0))
        self.assertAlmostEqual(metrics['precision'], 0.5)
        self.assertAlmostEqual(metrics['recall'], 1.0)

    def test_undefined_precision_not_claimed_perfect(self):
        metrics = prf(0, 0, 1)
        self.assertIsNone(metrics['precision'])
        self.assertEqual(metrics['recall'], 0.0)

if __name__ == '__main__':
    unittest.main()

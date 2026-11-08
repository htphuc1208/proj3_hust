#!/usr/bin/env python3
"""Verify delivered artifact bytes, current frozen engine and actual output schemas."""
import argparse
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from research_core import digest, load, now, save, validate_cdx


def verify(output):
    directories = [ROOT / 'runs' / name for name in ('m23-validation-v2', 'm23-controlled-repair-v2',
                                                    'm23-information-ablation-v3', 'm23-dsn-b4-v2')]
    files, schemas = 0, 0
    for directory in directories:
        manifest = load(directory / 'run_manifest.json')
        for relative, record in manifest['artifacts'].items():
            path = (directory / relative).resolve()
            if not path.is_relative_to(directory.resolve()):
                raise ValueError('Artifact path escapes bundle')
            assert digest(path) == record['sha256'], str(path)
            files += 1
        summary = directory / 'counterfactual_evidence_repair.json'
        if summary.exists():
            report = load(summary)
            for relative, expected in report['frozen_code'].items():
                assert digest(ROOT / relative) == expected, 'Frozen engine changed: ' + relative
            for relative, expected in report['raw_input_hashes'].items():
                assert digest(ROOT / relative) == expected, 'Raw input changed: ' + relative
        for path in directory.rglob('schema_validation.json'):
            document = path.parent / 'reconstructed.cdx.json'
            if not document.exists():
                document = path.parent / 'normalized.cdx.json'
            assert validate_cdx(load(document))['valid'], str(document)
            schemas += 1
    ui = ROOT / 'results/research_workbench'
    browser = load(ui / 'browser_validation.json')
    build = load(ui / 'build_manifest.json')
    assert browser['status'] == 'PASS' and not browser['javascript_errors']
    assert digest(ui / 'index.html') == browser['index_sha256'] == build['output_sha256']
    for relative, expected in build['input_manifest_sha256'].items():
        assert digest(ROOT / relative / 'run_manifest.json') == expected
    tests = (ROOT / 'research/test_results.txt').read_text()
    count = int(re.search(r'Ran (\d+) tests', tests)[1])
    assert tests.rstrip().endswith('OK')
    result = {'status': 'PASS', 'verified_at': now(), 'registered_artifacts_verified': files,
              'schema_documents_validated': schemas, 'frozen_engine_matches_current_source': True,
              'raw_legacy_inputs_unchanged': True, 'unit_tests_passed': count,
              'unit_test_log_sha256': digest(ROOT / 'research/test_results.txt'),
              'browser_acceptance': browser, 'screenshot_sha256': {name: digest(ui / name) for name in browser['screenshots']},
              'scientific_status': 'Implemented; DSN partial reproduction; no claim of zero algorithmic failures',
              'deferred': ['Agent experiments', 'B5/B6', 'New repository cohort', '2026 topology replication'],
              'ml_training_authorized': False, 'model_api_calls': 0}
    save(output, result)
    print({key: result[key] for key in ('status', 'registered_artifacts_verified', 'schema_documents_validated', 'unit_tests_passed')})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT / 'research/verification.json')
    verify(parser.parse_args().out)

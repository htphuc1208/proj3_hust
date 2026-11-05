"""Synthetic interrupted transfers: transport integrity, not empirical SBOM quality."""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.request import Request, urlopen

from packaging.tags import Tag
from sbom_recovery.artifact_cache import ArtifactCache
from sbom_recovery.wheel_acquisition import lock_pins, select_wheel


class ArtifactCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.payload = b'synthetic-wheel-bytes-' * 20000
        self.sha = sha256(self.payload).hexdigest()
        self.requests = []; self.mode = 'interrupt'
        fixture = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(inner):
                value = inner.headers.get('Range'); fixture.requests.append(value)
                start = int(value[6:-1]) if value else 0
                partial = value and fixture.mode != 'ignore_range'
                inner.send_response(206 if partial else 200)
                if partial:
                    inner.send_header('Content-Range', f'bytes {start}-{len(fixture.payload)-1}/{len(fixture.payload)}')
                else:
                    start = 0
                inner.send_header('Content-Length', str(len(fixture.payload) - start)); inner.end_headers()
                if len(fixture.requests) == 1 and fixture.mode in ('interrupt', 'ignore_range'):
                    inner.wfile.write(fixture.payload[:131072]); inner.wfile.flush(); inner.close_connection = True
                else:
                    inner.wfile.write(fixture.payload[start:])
            def log_message(self, *args):
                pass
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.addCleanup(self.close)
        def transport(request, timeout):
            return urlopen(Request(f'http://127.0.0.1:{self.server.server_port}/wheel', headers=dict(request.header_items())), timeout=timeout)
        self.store = ArtifactCache(self.temp.name, open_url=transport, pause=lambda _: None)

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=3)

    def obtain(self, **changes):
        return self.store.obtain(**{'url':'https://files.pythonhosted.org/synthetic.whl','sha256':self.sha,
                'size':len(self.payload),'filename':'fixture-1-py3-none-any.whl', **changes})

    def test_resumes_an_actual_interrupted_http_response_and_verifies_digest(self):
        result = self.obtain()
        self.assertEqual(Path(result['path']).read_bytes(), self.payload)
        self.assertEqual(self.requests, [None, 'bytes=131072-'])
        self.assertEqual(result['resumed_requests'], 1)
        self.assertEqual(self.obtain()['cache_hit'], True)
        self.assertEqual(len(self.requests), 2)

    def test_range_ignored_restarts_instead_of_appending(self):
        self.mode = 'ignore_range'
        result = self.obtain()
        self.assertEqual(Path(result['path']).read_bytes(), self.payload)
        self.assertEqual(len(self.requests), 2)

    def test_digest_mismatch_is_not_admitted_or_silently_retried(self):
        self.mode = 'complete'
        with self.assertRaisesRegex(ValueError, 'DIGEST_MISMATCH'):
            self.obtain(sha256='0'*64)
        self.assertFalse((Path(self.temp.name)/('0'*64)/'fixture-1-py3-none-any.whl').exists())
        self.assertEqual(len(self.requests), 1)

    def test_two_builds_share_one_verified_download(self):
        self.mode = 'complete'
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: self.obtain(), range(2)))
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(sum(r['cache_hit'] for r in results), 1)

    def test_persistent_partial_file_survives_a_new_cache_instance(self):
        folder = Path(self.temp.name)/self.sha; folder.mkdir()
        (folder/'fixture-1-py3-none-any.whl.part').write_bytes(self.payload[:50000])
        self.mode = 'complete'
        self.assertEqual(Path(self.obtain()['path']).read_bytes(), self.payload)
        self.assertEqual(self.requests, ['bytes=50000-'])

    def test_external_origin_and_path_escape_fail_before_network(self):
        for change in [{'url':'https://untrusted.invalid/a.whl'},{'filename':'../a.whl'}, {'sha256':'../invalid'}]:
            with self.subTest(change=change), self.assertRaises(ValueError): self.obtain(**change)
        self.assertEqual(self.requests, [])


class WheelSelectionTests(unittest.TestCase):
    def pin(self):
        return {'name':'fixture','version':'1','hashes':['a'*64]}

    def wheel(self, **changes):
        return {'filename':'fixture-1-py3-none-any.whl','packagetype':'bdist_wheel','yanked':False,
                'digests':{'sha256':'a'*64},'size':100,'requires_python':'>=3.8',
                'upload_time_iso_8601':'2025-01-01T00:00:00Z',
                'url':'https://files.pythonhosted.org/fixture.whl', **changes}

    def select(self, rows, root_artifact=None):
        return select_wheel({'urls':rows},self.pin(),[Tag('py3','none','any')],
                            '2025-12-31T23:59:59Z','3.11.16',root_artifact)

    def test_lock_parser_keeps_exact_hashes_and_environment(self):
        text='fixture==1 \\\n    --hash=sha256:'+('a'*64)+'\n# via root\nwindows-only==2 ; sys_platform == "win32" \\\n    --hash=sha256:'+('b'*64)+'\n'
        self.assertEqual(lock_pins(text,{'sys_platform':'linux'}),[self.pin()])
        for bad in ['fixture>=1','fixture==1','fixture @ https://untrusted.invalid/a.whl']:
            with self.assertRaises(ValueError): lock_pins(bad)

    def test_wrong_hash_future_wheel_platform_or_python_are_not_fallbacks(self):
        for changed in [{'digests':{'sha256':'b'*64}}, {'upload_time_iso_8601':'2026-01-01T00:00:00Z'},
                        {'filename':'fixture-1-cp310-cp310-win_amd64.whl'}, {'requires_python':'>=3.12'}, {'yanked':True}]:
            with self.subTest(changed=changed),self.assertRaises(ValueError):self.select([self.wheel(**changed)])
        self.assertEqual(self.select([self.wheel()])['sha256'],'a'*64)

    def test_frozen_root_artifact_cannot_be_swapped_for_another_build(self):
        with self.assertRaises(ValueError):
            self.select([self.wheel()],{'filename':'fixture-1-1-py3-none-any.whl','sha256':'a'*64})


if __name__ == '__main__': unittest.main()

"""Digest-checked downloads with durable partial files and no overall retry quota.

Used by trusted benchmark construction, never to supply inference labels.
"""
from contextlib import closing
from datetime import datetime, timezone
import fcntl
import hashlib
import http.client
import json
from pathlib import Path
import re
import socket
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import uuid


def utc():
    return datetime.now(timezone.utc).isoformat()


def file_sha(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def public_url(url, host):
    parts = urlsplit(url)
    if parts.scheme != 'https' or parts.hostname != host or parts.username or parts.password or parts.port not in (None, 443):
        raise ValueError('Unexpected public artifact origin')


class ArtifactCache:
    """obtain() admits only the expected complete bytes; failures preserve progress.

    open_url/pause are internal transport seams for deterministic interrupted-
    download tests. Production requests use standard TLS verification.
    """

    def __init__(self, directory, *, open_url=urlopen, pause=time.sleep, on_event=None, stall_timeout=30):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.open_url, self.pause, self.on_event = open_url, pause, on_event
        self.stall_timeout = stall_timeout

    def event(self, **record):
        if self.on_event:
            self.on_event({'at': utc(), **record})

    def _delay(self, attempt):
        self.pause(min(30, 2 ** min(attempt - 1, 5)))

    def obtain(self, *, url, sha256, size, filename):
        public_url(url, 'files.pythonhosted.org')
        if (not re.fullmatch(r'[a-f0-9]{64}', sha256) or type(size) is not int or size < 0
                or Path(filename).name != filename or not filename.endswith('.whl') or '\\' in filename):
            raise ValueError('Invalid artifact identity')
        folder = self.directory / sha256
        if folder.is_symlink():
            raise ValueError('Artifact cache directory symlink denied')
        folder.mkdir(exist_ok=True)
        target, part = folder / filename, folder / (filename + '.part')
        if (folder/'.lock').is_symlink():
            raise ValueError('Artifact lock symlink denied')
        with (folder / '.lock').open('a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if target.is_symlink() or part.is_symlink():
                raise ValueError('Artifact cache symlink denied')
            if target.is_file():
                if target.stat().st_size == size and file_sha(target) == sha256:
                    self.event(status='CACHE_HIT', sha256=sha256)
                    return {'path': str(target), 'sha256': sha256, 'bytes': size, 'url': url,
                            'filename': filename, 'cache_hit': True, 'attempts': 0, 'verified_at': utc()}
                target.rename(folder / ('quarantined-' + uuid.uuid4().hex))
            attempts, resumes = 0, 0
            while True:
                offset = part.stat().st_size if part.is_file() else 0
                if offset > size:
                    part.rename(folder / ('quarantined-' + uuid.uuid4().hex))
                    raise ValueError('Partial artifact exceeds declared size')
                if offset == size:
                    if file_sha(part) != sha256:
                        part.rename(folder / ('quarantined-' + uuid.uuid4().hex))
                        raise ValueError('ARTIFACT_DIGEST_MISMATCH')
                    part.replace(target)
                    record = {'path': str(target), 'sha256': sha256, 'bytes': size, 'url': url,
                              'filename': filename, 'cache_hit': False, 'attempts': attempts,
                              'resumed_requests': resumes, 'verified_at': utc()}
                    (folder / 'receipt.json').write_text(json.dumps(record, indent=2) + '\n')
                    self.event(status='VERIFIED', sha256=sha256, bytes=size)
                    return record
                attempts += 1
                headers = {'Accept-Encoding': 'identity', 'User-Agent': 'sbom-independent-build/1'}
                if offset:
                    headers['Range'] = f'bytes={offset}-'
                self.event(status='DOWNLOADING', sha256=sha256, attempt=attempts, offset=offset, bytes=size)
                try:
                    with closing(self.open_url(Request(url, headers=headers), timeout=self.stall_timeout)) as response:
                        status = response.status
                        if status == 206:
                            match = re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)', response.headers.get('Content-Range', ''))
                            if (not match or int(match[1]) != offset or int(match[3]) != size
                                    or int(match[2]) < offset or int(match[2]) >= size):
                                raise ValueError('Invalid artifact Content-Range')
                            mode = 'ab' if offset else 'wb'
                            resumes += bool(offset)
                        elif status == 200:
                            # RFC 9110 permits a server to ignore Range: restart, never append.
                            offset, mode = 0, 'wb'
                        else:
                            raise ValueError('Unexpected artifact response status')
                        with part.open(mode) as output:
                            try:
                                while True:
                                    chunk = response.read(min(65536, size - offset + 1))
                                    if not chunk:
                                        break
                                    if offset + len(chunk) > size:
                                        raise ValueError('Artifact exceeds declared size')
                                    output.write(chunk)
                                    offset += len(chunk)
                            except http.client.IncompleteRead as exc:
                                if exc.partial and offset + len(exc.partial) <= size:
                                    output.write(exc.partial)
                                raise
                    if part.stat().st_size < size:
                        self.event(status='RETRYING', sha256=sha256, reason='INCOMPLETE_BODY')
                        self._delay(attempts)
                except HTTPError as exc:
                    if exc.code not in (408, 429, 500, 502, 503, 504):
                        raise RuntimeError(f'Artifact HTTP {exc.code}') from None
                    self.event(status='RETRYING', sha256=sha256, reason=f'HTTP_{exc.code}')
                    self._delay(attempts)
                except (URLError, socket.timeout, ConnectionError, http.client.IncompleteRead) as exc:
                    self.event(status='RETRYING', sha256=sha256, reason=type(exc).__name__)
                    self._delay(attempts)


def registry_json(url, *, open_url=urlopen, pause=time.sleep, on_event=None):
    """Fetch public release metadata; transient failures have no overall quota."""
    public_url(url, 'pypi.org')
    attempt = 0
    while True:
        attempt += 1
        try:
            with closing(open_url(Request(url, headers={'User-Agent': 'sbom-independent-build/1'}), timeout=30)) as response:
                raw = response.read()
            return raw, json.loads(raw)
        except HTTPError as exc:
            if exc.code not in (408, 429, 500, 502, 503, 504):
                raise RuntimeError(f'Registry HTTP {exc.code}') from None
        except (URLError, socket.timeout, ConnectionError, http.client.IncompleteRead):
            pass
        if on_event:
            on_event({'at': utc(), 'status': 'RETRYING_REGISTRY', 'attempt': attempt, 'url': url})
        pause(min(30, 2 ** min(attempt - 1, 5)))

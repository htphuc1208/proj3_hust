"""Reproducible public-tool acquisition. Original upstream source stays outside tracked code."""
from pathlib import Path
import hashlib
import io
import os
import shlex
import subprocess
import tarfile
from urllib.request import urlopen

from research_core import digest, load, now, save
from .baselines import UNIFIER_COMMIT, REPLICATION_COMMIT, upstream
from .storage import save

ROOT = Path(__file__).resolve().parents[1]
NINKA_COMMIT = "b94e0d36669c4cc086856adf57bc67ced8f1aaf0"


def bootstrap():
    work = ROOT / "research/.work"
    work.mkdir(parents=True, exist_ok=True)
    records = []
    for name, url, commit in (
        ("sbom-unifier", "https://github.com/MoriwakiYusuke/sbom-unifier.git", UNIFIER_COMMIT),
        ("sbom-unifier-replication", "https://github.com/MoriwakiYusuke/sbom-unifier-replication.git", REPLICATION_COMMIT),
        ("ninka", "https://github.com/dmgerman/ninka.git", NINKA_COMMIT)):
        path = work / name
        if not path.exists():
            subprocess.run(["git", "clone", "--no-checkout", url, str(path)], check=True, capture_output=True)
            subprocess.run(["git", "checkout", "--detach", commit], cwd=path, check=True, capture_output=True)
        upstream(path, commit)
        records.append({"tool": name, "source": url, "commit": commit})
    # Existing toolchain manifest pins both archive and binary SHA-256.
    toolchain = load(ROOT / "research/toolchain.json")
    for name in ("syft", "trivy"):
        spec = toolchain["tools"][name]
        executable = work / name
        if not executable.exists():
            with urlopen(spec["archive_url"], timeout=120) as response:
                data = response.read()
            if hashlib.sha256(data).hexdigest() != spec["archive_sha256"]:
                raise ValueError("Archive digest mismatch: " + name)
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                member = next(m for m in archive.getmembers() if m.name == name and m.isfile())
                executable.write_bytes(archive.extractfile(member).read())
            executable.chmod(0o755)
        if digest(executable) != spec["binary_sha256"]:
            raise ValueError("Binary digest mismatch: " + name)
        records.append({"tool": name, "version": spec["tag"], "sha256": digest(executable)})
    ms = work / "sbom-tool"
    ms_url = "https://github.com/microsoft/sbom-tool/releases/download/v4.1.5/sbom-tool-linux-x64"
    ms_digest = "bf5d4f99bc98c119d549d08fc02ae92598a7a42772f17317c01031a92632e05b"
    if not ms.exists():
        with urlopen(ms_url, timeout=120) as response:
            ms.write_bytes(response.read())
        ms.chmod(0o755)
    if digest(ms) != ms_digest:
        raise ValueError("Microsoft sbom-tool digest mismatch")
    records.append({"tool": "Microsoft sbom-tool", "version": "4.1.5", "source": ms_url, "sha256": ms_digest})
    # Install a pure-Perl dependency locally; do not modify system Perl.
    perl = work / "perl5/IO"
    perl.mkdir(parents=True, exist_ok=True)
    dependency = perl / "CaptureOutput.pm"
    cpan_url = "https://cpan.metacpan.org/authors/id/D/DA/DAGOLDEN/IO-CaptureOutput-1.1105.tar.gz"
    if not dependency.exists():
        with urlopen(cpan_url, timeout=30) as response:
            data = response.read()
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            member = next(m for m in archive.getmembers() if m.name.endswith("/lib/IO/CaptureOutput.pm") and m.isfile())
            dependency.write_bytes(archive.extractfile(member).read())
    tools = work / "tool-bin"
    tools.mkdir(exist_ok=True)
    wrapper = tools / "ninka"
    wrapper.write_text("#!/bin/sh\nexec perl -I " + shlex.quote(str(work / "perl5")) + " -I " + shlex.quote(str(work / "ninka/lib"))
                       + " " + shlex.quote(str(work / "ninka/bin/ninka")) + ' "$@"\n')
    wrapper.chmod(0o755)
    records.append({"tool": "IO::CaptureOutput", "version": "1.1105", "source": cpan_url, "module_sha256": digest(dependency)})
    provenance = {"schema_version": "agent-toolchain-v1", "acquired_at": now(), "tools": records,
                  "integrity_scope": "Frozen public acquisition bytes/commits; not a signature or build attestation"}
    save(ROOT / "research/agent_toolchain.json", provenance)
    return provenance

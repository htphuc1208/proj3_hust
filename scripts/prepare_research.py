#!/usr/bin/env python3
"""Fetch pinned primary artifacts and trusted scanner binaries, recording hashes."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from public_evidence import fetch
from research_core import digest, load, now, save

BENCHMARK_COMMIT = "e6bcf23b2f4e384f9fc398793529583845612b63"


def prepare():
    work = ROOT / "research/.work"
    work.mkdir(parents=True, exist_ok=True)
    lock_file = ROOT / "research/toolchain.json"
    lock = load(lock_file) if lock_file.exists() else {"frozen_at": now(), "tools": {}}
    # Pin the already available image by immutable local image ID, never a moving tag at execution.
    lock["image"] = subprocess.check_output(["docker", "image", "inspect", "sbom-benchmark-harness:3.11",
                                             "--format", "{{.Id}}"], text=True).strip()
    for name, repo, version in [("syft", "anchore/syft", "v1.54.1"), ("trivy", "aquasecurity/trivy", None)]:
        if name in lock["tools"]:
            version = lock["tools"][name]["tag"]
        endpoint = "tags/" + version if version else "latest"
        release = json.loads(fetch(f"https://api.github.com/repos/{repo}/releases/{endpoint}"))
        version = release["tag_name"]
        tar_name = f"syft_{version.lstrip('v')}_linux_amd64.tar.gz" if name == "syft" else f"trivy_{version.lstrip('v')}_Linux-64bit.tar.gz"
        checks_name = f"syft_{version.lstrip('v')}_checksums.txt" if name == "syft" else f"trivy_{version.lstrip('v')}_checksums.txt"
        assets = {a["name"]: a["browser_download_url"] for a in release["assets"]}
        archive, checks = work / tar_name, work / checks_name
        if not checks.exists():
            checks.write_bytes(fetch(assets[checks_name]))
        if not archive.exists():
            archive.write_bytes(fetch(assets[tar_name], limit=128 * 1024 * 1024))
        expected = next(line.split()[0] for line in checks.read_text().splitlines() if line.split()[-1].lstrip("*") == tar_name)
        if digest(archive) != expected:
            raise ValueError("Scanner release archive checksum mismatch")
        binary = work / name
        with tarfile.open(archive) as tar:
            member = next(m for m in tar.getmembers() if m.isfile() and m.name in (name, "./" + name))
            binary.write_bytes(tar.extractfile(member).read())
        binary.chmod(0o755)
        lock["tools"][name] = {"tag": version, "archive_url": assets[tar_name], "archive_sha256": expected,
                                "binary_sha256": digest(binary), "checksums_url": assets[checks_name],
                                "version_output": subprocess.check_output([str(binary), "version" if name == "syft" else "--version"], text=True).strip()}
        save(lock_file, lock)
    schemas = ROOT / "research/schemas"
    schemas.mkdir(exist_ok=True)
    provenance = []
    for name in ("bom-1.5.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"):
        path = schemas / name
        url = f"https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/{name}"
        if not path.exists():
            path.write_bytes(fetch(url))
        provenance.append({"filename": name, "url": url, "sha256": digest(path)})
    save(schemas / "provenance.json", provenance)
    papers = ROOT / "research/papers"
    papers.mkdir(exist_ok=True)
    paper = work / "sbom-dsn24.pdf"
    url = "https://cs.ucr.edu/~heng/pubs/sbom-dsn24.pdf"
    if not paper.exists():
        paper.write_bytes(fetch(url))
    checkout = work / "sbom-benchmark"
    if not checkout.exists():
        subprocess.run(["git", "clone", "--quiet", "https://github.com/DeepBitsTechnology/sbom-benchmark.git", str(checkout)], check=True)
    subprocess.run(["git", "-C", str(checkout), "checkout", "--quiet", "--detach", BENCHMARK_COMMIT], check=True)
    actual = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    assert actual == BENCHMARK_COMMIT
    save(papers / "dsn2024.json", {"authors": ["Sheng Yu", "Wei Song", "Xunchao Hu", "Heng Yin"],
        "title": "On the Correctness of Metadata-Based SBOM Generation: A Differential Analysis Approach",
        "venue": "IEEE/IFIP DSN", "year": 2024, "paper_url": url, "paper_sha256": digest(paper),
        "benchmark_repository": "https://github.com/DeepBitsTechnology/sbom-benchmark", "benchmark_commit": actual,
        "input_kind": "AUTHORED_METADATA_BENCHMARK", "entrypoints": ["python/req/requirements.txt", "python/req/r.txt"],
        "reproduction_scope": "Python requirements subset with pinned contemporary tools; not full-paper reproduction"})
    command = ["docker", "run", "--rm", "--network", "none", "--entrypoint", "python", lock["image"], "-c",
        "import json,platform,subprocess; from packaging.tags import sys_tags; print(json.dumps({'python_full_version':platform.python_version(), 'wheel_tags':[str(t) for t in sys_tags()], 'build_environment':json.loads(subprocess.check_output(['python','-m','pip','list','--format=json']))}))"]
    context = json.loads(subprocess.check_output(command, text=True))
    context["image"] = lock["image"]
    save(ROOT / "research/target_context.json", context)
    print(json.dumps({"toolchain": str(lock_file), "benchmark_commit": actual}))


if __name__ == "__main__":
    prepare()

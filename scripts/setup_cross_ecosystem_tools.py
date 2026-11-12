#!/usr/bin/env python3
"""Install isolated, release-pinned tools for the exploratory multi-language probe."""
from concurrent.futures import ThreadPoolExecutor
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "research/.work/cross-ecosystem-probe-v1"
OUT = ROOT / "runs/cross-ecosystem-probe-v1"
TOOLS = WORK / "tools"


def fetch(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "sbom-recovery-research/0.2"}), timeout=180).read()


def save(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2) + "\n")


def github_tool(name, pattern, binary, checksum_pattern=None):
    release = json.loads((OUT / "tool-metadata" / (name + ".json")).read_text())
    asset = next(x for x in release["assets"] if pattern in x["name"])
    path = TOOLS / binary
    if path.exists():
        return dict(tool=name, status="ALREADY_PRESENT", binary_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    data = fetch(asset["browser_download_url"])
    digest = hashlib.sha256(data).hexdigest()
    record = dict(tool=name, tag=release["tag_name"], url=asset["browser_download_url"], archive_sha256=digest)
    if checksum_pattern:
        checks = next(x for x in release["assets"] if checksum_pattern in x["name"])
        content = fetch(checks["browser_download_url"])
        (OUT / "tool-metadata" / (name + "-checksums.txt")).write_bytes(content)
        assert digest in content.decode(), (name, "release checksum mismatch")
        record["checksum_url"] = checks["browser_download_url"]
    else:
        record["checksum_note"] = "Recorded local hash; no separate upstream checksum verified"
    if asset["name"].endswith((".tar.gz", ".tar.xz")):
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            member = next(x for x in archive if Path(x.name).name == binary and x.isfile())
            path.write_bytes(archive.extractfile(member).read())
    else:
        path.write_bytes(data)
    path.chmod(0o755)
    record["binary_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    save(OUT / "tool-metadata" / (name + "-installed.json"), record)
    print(name, release["tag_name"], "installed", flush=True)
    return record


def go_toolchain():
    release = json.loads((OUT / "tool-metadata/go.json").read_text())[0]
    selected = next(x for x in release["files"] if x["os"] == "linux" and x["arch"] == "amd64" and x["kind"] == "archive")
    if (TOOLS / "go/bin/go").exists():
        return dict(tool="go", status="ALREADY_PRESENT")
    url = "https://go.dev/dl/" + selected["filename"]
    data = fetch(url)
    assert hashlib.sha256(data).hexdigest() == selected["sha256"]
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        archive.extractall(TOOLS, filter="data")
    record = dict(tool="go", version=release["version"], url=url, archive_sha256=selected["sha256"])
    save(OUT / "tool-metadata/go-installed.json", record)
    print("go", release["version"], "installed", flush=True)
    return record


def npm_tools():
    destination = TOOLS / "node"
    if (destination / "node_modules/.bin/cdxgen").exists():
        return dict(tool="node-tools", status="ALREADY_PRESENT")
    specs = []
    for name, package in [("cdxgen", "@cyclonedx/cdxgen"), ("cyclonedx-npm", "@cyclonedx/cyclonedx-npm"), ("esbuild", "esbuild")]:
        metadata = json.loads((OUT / "tool-metadata" / (name + ".json")).read_text())
        specs.append(package + "@" + metadata["version"])
    destination.mkdir(exist_ok=True)
    command = ["npm", "install", "--prefix", str(destination), "--no-audit", "--no-fund", *specs]
    result = subprocess.run(command, capture_output=True, text=True, timeout=600)
    (OUT / "tool-metadata/npm-install.stdout").write_text(result.stdout)
    (OUT / "tool-metadata/npm-install.stderr").write_text(result.stderr)
    save(OUT / "tool-metadata/npm-install.execution.json", dict(command=command, exit_code=result.returncode))
    assert result.returncode == 0, result.stderr[-2000:]
    (OUT / "tool-metadata/tool-package-lock.json").write_bytes((destination / "package-lock.json").read_bytes())
    print("node tools installed", specs, flush=True)
    return dict(tool="node-tools", specs=specs, status="COMPLETE")


def rust_toolchain():
    release = tomllib.loads((OUT / "tool-metadata/rust.txt").read_text())
    prefix = TOOLS / "rust"
    if (prefix / "bin/cargo").exists():
        return dict(tool="rust", status="ALREADY_PRESENT")
    records = []
    for component in ["rustc", "rust-std", "cargo"]:
        selected = release["pkg"][component]["target"]["x86_64-unknown-linux-gnu"]
        data = fetch(selected["xz_url"])
        assert hashlib.sha256(data).hexdigest() == selected["xz_hash"]
        staging = WORK / "rust-install" / component
        staging.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            archive.extractall(staging, filter="data")
        installer = next(staging.glob("*/install.sh"))
        result = subprocess.run(["bash", str(installer), "--prefix=" + str(prefix), "--disable-ldconfig"],
                                cwd=installer.parent, capture_output=True, text=True, timeout=180)
        (OUT / "tool-metadata" / (component + "-install.stdout")).write_text(result.stdout)
        assert result.returncode == 0, result.stderr
        records.append(dict(component=component, url=selected["xz_url"], sha256=selected["xz_hash"]))
        print(component, "installed", flush=True)
    record = dict(tool="rust", version=release["pkg"]["rust"]["version"], components=records)
    save(OUT / "tool-metadata/rust-installed.json", record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust", action="store_true")
    args = parser.parse_args()
    TOOLS.mkdir(parents=True, exist_ok=True)
    tasks = [
        lambda: github_tool("syft", "linux_amd64.tar.gz", "syft", "checksums.txt"),
        lambda: github_tool("trivy", "Linux-64bit.tar.gz", "trivy", "checksums.txt"),
        lambda: github_tool("cyclonedx-gomod", "linux_amd64.tar.gz", "cyclonedx-gomod", "checksums.txt"),
        lambda: github_tool("cargo-cyclonedx", "x86_64-unknown-linux-gnu.tar.xz", "cargo-cyclonedx", "sha256.sum"),
        lambda: github_tool("osv-scanner", "osv-scanner_linux_amd64", "osv-scanner"),
        go_toolchain,
        npm_tools,
    ]
    if args.rust:
        tasks = [rust_toolchain, lambda: github_tool("cargo-auditable", "x86_64-unknown-linux-gnu.tar.xz", "cargo-auditable", "sha256.sum")]
    def invoke(fn):
        try:
            return fn()
        except Exception as exc:
            print("setup failure", str(exc), flush=True)
            return dict(status="FAILED", error=str(exc))
    with ThreadPoolExecutor(5) as executor:
        rows = list(executor.map(invoke, tasks))
    save(OUT / ("rust-tool-setup.json" if args.rust else "tool-setup.json"), rows)


if __name__ == "__main__":
    main()

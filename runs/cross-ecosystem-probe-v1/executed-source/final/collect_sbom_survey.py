#!/usr/bin/env python3
"""Freeze primary-source URLs and download research/tool metadata for a survey.

Downloaded publications stay in the ignored work cache. The reviewable bundle
contains acquisition status, hashes and release metadata, not redistributed PDFs.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import urllib.request
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "research/.work/cross-ecosystem-probe-v1"
OUT = ROOT / "runs/cross-ecosystem-probe-v1"
SOURCES = {
    "dsn2024": ("paper", "https://www.cs.ucr.edu/~heng/pubs/sbom-dsn24.pdf"),
    "cofano-python": ("paper", "https://arxiv.org/html/2409.01214"),
    "pip-sbom": ("paper", "https://arxiv.org/html/2409.06390"),
    "jbomaudit": ("paper", "https://www.xiaojingliao.com/uploads/9/7/0/2/97024238/xiao25jbomaudit.pdf"),
    "jbomaudit-artifact": ("artifact", "https://raw.githubusercontent.com/code-genome/jbomaudit/main/README.md"),
    "scored2024-impact": ("paper", "https://www.cs.montana.edu/izurieta/pubs/SCORED2024.pdf"),
    "reality-check-v2": ("paper", "https://arxiv.org/html/2511.20313v2"),
    "component-inclusion-v3": ("paper", "https://arxiv.org/html/2606.02442v3"),
    "mind-the-gap": ("paper", "https://arxiv.org/pdf/2609.19920"),
    "standards-tools-gap": ("paper", "https://arxiv.org/html/2601.05622v1"),
    "github-sbom": ("paper", "https://arxiv.org/html/2607.04614v1"),
    "omnibor": ("paper", "https://arxiv.org/html/2402.08980"),
    "no-edges": ("paper", "https://arxiv.org/html/2607.22140v4"),
    "code-component-trees": ("paper", "https://www.nature.com/articles/s41598-025-29762-0"),
    "syft-catalogers": ("official-doc", "https://oss.anchore.com/docs/guides/sbom/catalogers/"),
    "syft-java": ("official-doc", "https://oss.anchore.com/docs/capabilities/java/"),
    "syft-go": ("official-doc", "https://oss.anchore.com/docs/capabilities/golang/"),
    "trivy-sbom": ("official-doc", "https://trivy.dev/docs/latest/target/sbom/"),
    "trivy-coverage": ("official-doc", "https://trivy.dev/docs/latest/coverage/language/"),
    "npm-sbom": ("official-doc", "https://docs.npmjs.com/cli/v10/commands/npm-sbom/"),
    "npm-package-spec": ("official-doc", "https://docs.npmjs.com/cli/v10/using-npm/package-spec/"),
    "esbuild-metafile": ("official-doc", "https://esbuild.github.io/api/#metafile"),
    "maven-shade": ("official-doc", "https://maven.apache.org/plugins/maven-shade-plugin/examples/executable-jar.html"),
    "maven-dependency-mechanism": ("official-doc", "https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html"),
    "cargo-features": ("official-doc", "https://doc.rust-lang.org/cargo/reference/features.html"),
    "cargo-metadata": ("official-doc", "https://doc.rust-lang.org/cargo/commands/cargo-metadata.html"),
    "cargo-auditable": ("official-tool", "https://raw.githubusercontent.com/rust-secure-code/cargo-auditable/master/README.md"),
    "cdx-cargo": ("official-tool", "https://raw.githubusercontent.com/CycloneDX/cyclonedx-rust-cargo/main/README.md"),
    "cdx-gomod": ("official-tool", "https://raw.githubusercontent.com/CycloneDX/cyclonedx-gomod/main/README.md"),
    "go-mod": ("official-doc", "https://go.dev/ref/mod"),
    "govulncheck": ("official-doc", "https://go.dev/security/vuln/"),
    "cdx-npm": ("official-tool", "https://raw.githubusercontent.com/CycloneDX/cyclonedx-node-npm/main/README.md"),
    "cdxgen": ("official-tool", "https://raw.githubusercontent.com/CycloneDX/cdxgen/master/README.md"),
    "osv-scanner": ("official-doc", "https://google.github.io/osv-scanner/supported-languages-and-lockfiles/"),
    "osv-api": ("official-doc", "https://google.github.io/osv.dev/api/"),
    "dotnet-sbom": ("official-tool", "https://raw.githubusercontent.com/CycloneDX/cyclonedx-dotnet/master/README.md"),
    "dotnet-trimming": ("official-doc", "https://learn.microsoft.com/en-us/dotnet/core/deploying/trimming/trim-self-contained"),
    "bomsh": ("official-tool", "https://raw.githubusercontent.com/omnibor/bomsh/main/README.md"),
    "cisa-sbom-types": ("official-doc", "https://www.cisa.gov/sites/default/files/2023-04/sbom-types-document-508c.pdf"),
}
RELEASES = {
    "syft": "https://api.github.com/repos/anchore/syft/releases/latest",
    "trivy": "https://api.github.com/repos/aquasecurity/trivy/releases/latest",
    "cyclonedx-gomod": "https://api.github.com/repos/CycloneDX/cyclonedx-gomod/releases/latest",
    "cargo-cyclonedx": "https://api.github.com/repos/CycloneDX/cyclonedx-rust-cargo/releases/latest",
    "osv-scanner": "https://api.github.com/repos/google/osv-scanner/releases/latest",
    "grype": "https://api.github.com/repos/anchore/grype/releases/latest",
    "cdxgen": "https://registry.npmjs.org/@cyclonedx/cdxgen/latest",
    "cyclonedx-npm": "https://registry.npmjs.org/@cyclonedx/cyclonedx-npm/latest",
    "esbuild": "https://registry.npmjs.org/esbuild/latest",
    "go": "https://go.dev/dl/?mode=json",
    "rust": "https://static.rust-lang.org/dist/channel-rust-stable.toml",
    "cdx-maven": "https://repo.maven.apache.org/maven2/org/cyclonedx/cyclonedx-maven-plugin/maven-metadata.xml",
}


def save(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


def download(entry):
    key, (kind, url) = entry
    record = dict(id=key, kind=kind, url=url,
                  retrieved_at=datetime.now(timezone.utc).isoformat())
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "sbom-recovery-research/0.2"})
        with urllib.request.urlopen(request, timeout=75) as response:
            data = response.read()
            record.update(status=response.status, final_url=response.url,
                          content_type=response.headers.get("Content-Type"))
        extension = ".pdf" if data.startswith(b"%PDF") else ".json" if data[:1] in (b"{", b"[") else ".txt"
        path = WORK / "sources" / (key + extension)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        record.update(sha256=hashlib.sha256(data).hexdigest(), bytes=len(data), cache=str(path.relative_to(ROOT)))
        if kind == "release":
            destination = OUT / "tool-metadata" / path.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
    except Exception as exc:
        record.update(status="FAILED", error=str(exc))
    print(key, record["status"], flush=True)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--releases-only", action="store_true")
    args = parser.parse_args()
    entries = {} if args.releases_only else dict(SOURCES)
    entries.update({k: ("release", v) for k, v in RELEASES.items()})
    with ThreadPoolExecutor(8) as executor:
        rows = list(executor.map(download, entries.items()))
    save(OUT / ("release-acquisition.json" if args.releases_only else "source-acquisition.json"), rows)


if __name__ == "__main__":
    main()

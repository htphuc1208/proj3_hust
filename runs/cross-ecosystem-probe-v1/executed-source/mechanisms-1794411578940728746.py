#!/usr/bin/env python3
"""Causal controls and fixed-consumer comparisons for the exploratory survey."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request
import zipfile
import hashlib
import io

from run_cross_ecosystem_probe import (WORK, OUT, TOOLS, NODEBIN, execute, save, sha,
                                      go_env, rust_env, scan_one, snapshot, JAVA_POM, write)


def json_stream(text):
    decoder = json.JSONDecoder()
    rows = []
    while text.strip():
        text = text.lstrip()
        value, length = decoder.raw_decode(text)
        rows.append(value)
        text = text[length:]
    return rows


def variants():
    out = OUT / "mechanism-controls"
    original = WORK / "go-build"
    control = WORK / "go-without-inactive-replace"
    shutil.copytree(original, control, dirs_exist_ok=True)
    (control / "go.mod").write_text("\n".join(line for line in (original / "go.mod").read_text().splitlines()
                                              if not line.startswith("replace golang.org/x/text")) + "\n")
    execute(["go", "list", "-m", "-json", "all"], out, "go-no-inactive-replace-modules", cwd=control, env=go_env(), required=True)
    def identity(text):
        return sorted((row["Path"], row.get("Version"), row.get("Replace", {}).get("Path"),
                       row.get("Replace", {}).get("Version")) for row in json_stream(text))
    same = identity((out / "go-no-inactive-replace-modules.stdout").read_text()) == identity((OUT / "go-build/go-modules.stdout").read_text())
    assert same, "inactive replacement removal changed Go's actual module selection"
    save(out / "go-inactive-replace-control.json", dict(same_native_resolved_identities=same,
        original_go_mod_sha256=sha(original / "go.mod"), control_go_mod_sha256=sha(control / "go.mod"),
        kind="Controlled source representation change; no claim of a second independent application"))
    scan_one(("go-no-inactive-replace", "go-without-inactive-replace", "go"))
    execute([TOOLS / "syft", "scan", "dir:" + str(original), "-o", "cyclonedx-json=" + str(out / "go-syft-packages-lib.cdx.json")],
            out, "go-syft-packages-lib", env={**go_env(), "SYFT_GOLANG_USE_PACKAGES_LIB":"true"}, timeout=300)

    original = WORK / "rust-source"
    control = WORK / "rust-no-alias"
    shutil.copytree(original, control, dirs_exist_ok=True)
    (control / "Cargo.toml").write_text((original / "Cargo.toml").read_text().replace(
        'regex_alias = { package = "regex", version = "=1.5.4" }', 'regex = "=1.5.4"'))
    (control / "src/main.rs").write_text((original / "src/main.rs").read_text().replace("regex_alias::", "regex::"))
    execute(["cargo", "tree", "--target=x86_64-unknown-linux-gnu", "--edges=normal,build", "--prefix=none", "--format={p}"],
            out, "rust-no-alias-tree", cwd=control, env=rust_env(), required=True)
    def children(path):
        return sorted(path.read_text().splitlines()[1:])
    same = children(out / "rust-no-alias-tree.stdout") == children(OUT / "rust-build/cargo-tree-production.stdout")
    assert same and sha(control / "Cargo.lock") == sha(original / "Cargo.lock")
    save(out / "rust-alias-control.json", dict(same_production_tree_identities=same, identical_cargo_lock=True,
        cargo_lock_sha256=sha(original / "Cargo.lock"), original_manifest_sha256=sha(original / "Cargo.toml"),
        control_manifest_sha256=sha(control / "Cargo.toml"), kind="Dependency alias spelling only; same registry dependency closure"))
    scan_one(("rust-no-alias", "rust-no-alias", "rust"))
    execute([TOOLS / "trivy", "fs", "--include-dev-deps", "--offline-scan", "--skip-db-update", "--skip-java-db-update",
             "--disable-telemetry", "--skip-version-check", "--format", "cyclonedx", "--output", out / "rust-trivy-include-dev.cdx.json", original],
            out, "rust-trivy-include-dev")
    snapshot(control, out / "rust-no-alias", ["Cargo.toml", "Cargo.lock", "src/main.rs"])

    native = json.loads((OUT / "npm-alias/cyclonedx-npm-production.cdx.json").read_text())
    without_edges = dict(native)
    without_edges.pop("dependencies", None)
    save(out / "npm-native-no-edges.cdx.json", without_edges)
    assert without_edges["components"] == native["components"]
    save(out / "graph-control.json", dict(unchanged_components=True,
        original_sha256=sha(OUT / "npm-alias/cyclonedx-npm-production.cdx.json"),
        no_edges_sha256=sha(out / "npm-native-no-edges.cdx.json")))

    meta = json.loads((OUT / "npm-alias/esbuild-metafile.json").read_text())
    hashes = {name: sha(WORK / "npm-alias" / name) for name in meta["inputs"]}
    save(out / "bundle-input-hashes.json", dict(inputs=hashes,
        bundled_package_manifest_sha256=sha(WORK / "npm-alias/node_modules/lodash-vulnerable/package.json"),
        source_artifact_sha256=sha(WORK / "npm-bundle/app.js"),
        note="Metafile names are joined to original installed metadata; filenames alone do not identify registry packages"))
    spectrum = WORK / "spectrum"
    snapshot(spectrum, OUT / "spectrum", ["package.json", "yarn.lock"])
    save(OUT / "spectrum/acquisition.json", dict(url="https://github.com/withspectrum/spectrum",
        commit=subprocess.check_output(["git", "-C", str(spectrum), "rev-parse", "HEAD"], text=True).strip(),
        git_status=subprocess.check_output(["git", "-C", str(spectrum), "status", "--porcelain"], text=True),
        note="Contemporary checkout of a project named in Mind the Gap; original committed lock, no fresh install; not a reproduction of that paper's exact revision"))
    author = OUT / "java-jbomaudit/author-aaa-cli-jar-0.15.2-cyclonedx.json"
    shutil.copyfile(author, OUT / "java-jbomaudit/author.cdx.json")
    save(OUT / "java-jbomaudit/consumer-filename-control.json", dict(
        original_sha256=sha(author), renamed_sha256=sha(OUT / "java-jbomaudit/author.cdx.json"),
        note="OSV-Scanner rejects the author's original filename. Byte-identical copy uses .cdx.json; earlier failure retained."))


def real_and_packaging():
    project = WORK / "webpki-roots"
    out = OUT / "webpki-roots"
    lock_before = sha(project / "Cargo.lock")
    execute(["cargo", "tree", "-p", "webpki-roots", "--locked", "--target=x86_64-unknown-linux-gnu",
             "--edges=normal,build", "--prefix=none", "--format={p}"], out, "cargo-tree-production",
            cwd=project, env=rust_env(), timeout=240)
    snapshot(project, out, ["Cargo.toml", "Cargo.lock", "*/Cargo.toml"])
    save(out / "acquisition.json", dict(url="https://github.com/rustls/webpki-roots",
        commit=subprocess.check_output(["git", "-C", str(project), "rev-parse", "HEAD"], text=True).strip(),
        lock_unchanged=lock_before == sha(project / "Cargo.lock"),
        selection="Purposive follow-up: publicly maintained Rust workspace uses a renamed dependency; not a random sample"))
    scan_one(("webpki-roots-source", "webpki-roots", "rust"))

    # A real paper JAR is independently checked against upstream class bytes.
    url = "https://repo.maven.apache.org/maven2/org/apache/commons/commons-text/1.9/commons-text-1.9.jar"
    data = urllib.request.urlopen(url, timeout=60).read()
    expected = urllib.request.urlopen(url + ".sha512", timeout=60).read().decode().strip()
    assert hashlib.sha512(data).hexdigest() == expected
    upstream_cache = WORK / "commons-text-1.9.jar"
    upstream_cache.write_bytes(data)
    actual = WORK / "java-jbomaudit/aaa-cli-jar-0.15.2.jar"
    with zipfile.ZipFile(io.BytesIO(data)) as origin, zipfile.ZipFile(actual) as shipped:
        matches, modified = {}, []
        for name in shipped.namelist():
            if not name.startswith("org/apache/commons/text/") or not name.endswith(".class"):
                continue
            value = shipped.read(name)
            if name in origin.namelist() and value == origin.read(name):
                matches[name] = hashlib.sha256(value).hexdigest()
            else:
                modified.append(name)
    save(OUT / "java-jbomaudit/commons-text-class-evidence.json", dict(url=url, sha512=expected,
        upstream_jar_sha256=sha(upstream_cache), paper_jar_sha256=sha(actual), exact_class_matches=matches,
        nonmatching_classes=modified,
        note="Exact byte matches support component identification; neither prove vulnerable function reachability nor uniquely distinguish every upstream release"))

    project = WORK / "java-minimized-build"
    out = OUT / "java-minimized"
    pom = JAVA_POM.replace("<createDependencyReducedPom>false</createDependencyReducedPom>",
                           "<createDependencyReducedPom>false</createDependencyReducedPom><minimizeJar>true</minimizeJar>")
    write(project / "pom.xml", pom)
    write(project / "src/main/java/org/example/App.java", '''package org.example;
public class App { public static void main(String[] args) { System.out.println("SBOM"); } }
''')
    image = json.loads((OUT / "java-shade/image.json").read_text())["id"]
    cmd = ["docker", "run", "--rm", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=2g",
           "--user", f"{__import__('os').getuid()}:{__import__('os').getgid()}", "-e", "MAVEN_CONFIG=/tmp/maven",
           "-v", f"{project}:/project", "-v", f"{WORK / 'maven-cache'}:/m2", "-w", "/project", image,
           "mvn", "-B", "-Dmaven.repo.local=/m2", "-Duser.home=/tmp", "-DskipTests", "package",
           "org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom", "-DoutputFormat=json", "-DincludeTestScope=false"]
    execute(cmd, out, "maven-build", timeout=600, required=True)
    target = WORK / "java-minimized"
    target.mkdir(exist_ok=True)
    shutil.copyfile(project / "target/sbom-shade-probe-1.0.0.jar", target / "app.jar")
    shutil.copyfile(project / "target/bom.json", out / "cyclonedx-maven.cdx.json")
    with zipfile.ZipFile(target / "app.jar") as archive:
        commons = [name for name in archive.namelist() if name.startswith("org/apache/commons/compress/") and name.endswith(".class")]
        metadata = [name for name in archive.namelist() if "commons-compress" in name]
        classes = [name for name in archive.namelist() if name.endswith(".class")]
    assert not commons
    save(out / "artifact.json", dict(sha256=sha(target / "app.jar"), commons_compress_classes=commons,
        surviving_metadata=metadata, all_classes=classes, build_variant="maven-shade minimizeJar=true, unused direct dependency",
        note="Declared/build dependency remains true. No commons-compress bytecode is shipped in this JAR; package CVEs do not establish exposure."))
    execute(["docker", "run", "--rm", "--network", "none", "--read-only", "-v", f"{target}:/artifact:ro",
             image, "java", "-cp", "/artifact/app.jar", "org.example.App"], out, "smoke", required=True)
    snapshot(project, out, ["pom.xml", "src/main/java/org/example/App.java"])
    scan_one(("java-minimized", "java-minimized", "jar"))


def advisory_sets(path):
    data = json.loads(path.read_text())
    rows = {}
    for result in data.get("results", []):
        for package in result.get("packages", []):
            identity = package["package"]
            key = identity.get("ecosystem", "") + ":" + identity["name"] + "@" + identity.get("version", "")
            rows[key] = sorted(v["id"] for v in package.get("vulnerabilities", []))
    return rows


def consumers():
    cases = {
        "npm-native": "npm-alias/cyclonedx-npm-production.cdx.json",
        "npm-no-edges": "mechanism-controls/npm-native-no-edges.cdx.json",
        "npm-source-trivy": "scans/npm-source/trivy.cdx.json",
        "npm-installed-syft": "scans/npm-installed/syft-installed.cdx.json",
        "npm-bundle-syft": "scans/npm-bundle/syft.cdx.json",
        "java-native": "java-shade/cyclonedx-maven.cdx.json",
        "java-shaded-syft": "scans/java-shaded/syft.cdx.json",
        "java-no-metadata-syft": "scans/java-no-metadata/syft.cdx.json",
        "java-author": "java-jbomaudit/author.cdx.json",
        "java-published-syft": "scans/java-jbomaudit/syft.cdx.json",
        "java-published-trivy": "scans/java-jbomaudit/trivy-rootfs.cdx.json",
        "java-published-cdxgen": "scans/java-jbomaudit/cdxgen.cdx.json",
        "java-minimized-native": "java-minimized/cyclonedx-maven.cdx.json",
        "java-minimized-syft": "scans/java-minimized/syft.cdx.json",
        "go-source-syft": "scans/go-source/syft.cdx.json",
        "go-app-native": "go-build/cyclonedx-app.cdx.json",
        "rust-source-trivy": "scans/rust-source/trivy.cdx.json",
        "rust-no-alias-trivy": "scans/rust-no-alias/trivy.cdx.json",
        "rust-include-dev-trivy": "mechanism-controls/rust-trivy-include-dev.cdx.json",
        "rust-native": "rust-build/cyclonedx-target.cdx.json",
        "rust-binary-syft": "scans/rust-binary/syft.cdx.json",
        "rust-auditable-syft": "scans/rust-auditable/syft.cdx.json",
    }
    def run(item):
        name, relative = item
        path = OUT / relative
        if not path.exists():
            return dict(case=name, status="MISSING_INPUT")
        out = OUT / "consumers" / name
        # Explicit SBOM input only; disable resolution/call analysis to isolate
        # inventory-to-advisory matching. Exit 1 normally means vulnerabilities.
        result = execute([TOOLS / "osv-scanner", "scan", "source", "--no-resolve", "--no-call-analysis=go",
                          "--format=json", "--all-packages", "--all-vulns", "--sbom", path], out, "osv", timeout=240)
        record = dict(case=name, sbom=relative, sbom_sha256=sha(path), exit_code=result["exit_code"])
        try:
            record["packages"] = advisory_sets(out / "osv.stdout")
            record["has_parseable_json"] = True
        except (ValueError, KeyError):
            record.update(status="NO_PARSEABLE_RESULTS", has_parseable_json=False)
        save(out / "summary.json", record)
        return record
    with ThreadPoolExecutor(4) as executor:
        results = list(executor.map(run, cases.items()))
    save(OUT / "consumer-summary.json", results)
    by_name = {r["case"]: r for r in results}
    original, control = by_name["npm-native"], by_name["npm-no-edges"]
    assert original.get("has_parseable_json") and control.get("has_parseable_json")
    save(OUT / "mechanism-controls/graph-consumer-result.json", dict(
        identical_package_advisory_sets=original["packages"] == control["packages"],
        scanner="OSV-Scanner 2.7.1, --no-resolve, package matching only",
        note="One consumer/configuration; not evidence that dependency graphs never matter"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["variants", "real", "consumers", "all"])
    args = parser.parse_args()
    frozen = OUT / "executed-source" / ("mechanisms-" + str(time.time_ns()) + ".py")
    frozen.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(Path(__file__), frozen)
    if args.phase in ["variants", "all"]:
        variants()
    if args.phase in ["real", "all"]:
        real_and_packaging()
    if args.phase in ["consumers", "all"]:
        consumers()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Exploratory mechanisms, not a representative cross-language benchmark.

Real upstream dependencies and one published Java artifact, with controlled
build/representation variants. Source, installed and shipped scopes stay apart.
All commands and failures are recorded. No production recovery code is called.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "research/.work/cross-ecosystem-probe-v1"
OUT = ROOT / "runs/cross-ecosystem-probe-v1"
TOOLS = WORK / "tools"
NODEBIN = TOOLS / "node/node_modules/.bin"


def save(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(command, out, label, *, cwd=None, env=None, timeout=600, required=False):
    out.mkdir(parents=True, exist_ok=True)
    record = dict(command=list(map(str, command)), cwd=str(cwd) if cwd else None,
                  started_at=datetime.now(timezone.utc).isoformat(), environment_overrides=env or {})
    start = time.monotonic()
    try:
        result = subprocess.run(record["command"], cwd=cwd, env={**os.environ, **(env or {})},
                                capture_output=True, text=True, timeout=timeout)
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as exc:
        code = 124
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
    except OSError as exc:
        code, stdout, stderr = 127, "", str(exc)
    (out / (label + ".stdout")).write_text(stdout)
    (out / (label + ".stderr")).write_text(stderr)
    record.update(exit_code=code, seconds=time.monotonic() - start)
    save(out / (label + ".execution.json"), record)
    print(label, code, round(record["seconds"], 2), flush=True)
    if required and code:
        raise RuntimeError(f"{label}: {stderr[-1200:]}")
    return record


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def snapshot(source, out, patterns):
    hashes = {}
    for pattern in patterns:
        for path in source.glob(pattern):
            if path.is_file():
                relative = path.relative_to(source)
                destination = out / "input" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
                hashes[str(relative)] = sha(path)
    save(out / "input-manifest.json", dict(source=str(source), files=hashes))


def npm_probe():
    project = WORK / "npm-alias"
    out = OUT / "npm-alias"
    project.mkdir(parents=True, exist_ok=True)
    save(project / "package.json", {
        "name": "sbom-alias-build-probe", "version": "1.0.0", "private": True,
        "dependencies": {"lodash-vulnerable": "npm:lodash@4.17.20", "lodash-fixed": "npm:lodash@4.17.21"},
        "devDependencies": {"minimist": "1.2.5"}, "optionalDependencies": {"fsevents": "2.1.3"}})
    write(project / "index.js", "const template = require('lodash-vulnerable/template');\nconsole.log(template('hello <%= name %>')({name: 'SBOM'}));\n")
    execute(["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund"], out, "install", cwd=project, required=True)
    execute(["npm", "ls", "--all", "--json"], out, "npm-ls", cwd=project)
    inventory = []
    for path in sorted((project / "node_modules").glob("*/package.json")):
        data = json.loads(path.read_text())
        inventory.append(dict(path=str(path.relative_to(project)), name=data["name"], version=data["version"], sha256=sha(path)))
    save(out / "installed-inventory.json", dict(platform="linux", architecture="x86_64", packages=inventory))
    for name, extra in [("all", []), ("production", ["--omit=dev", "--omit=optional"])]:
        execute(["npm", "sbom", "--sbom-format=cyclonedx", *extra], out, "npm-sbom-" + name, cwd=project)
        src = out / ("npm-sbom-" + name + ".stdout")
        if src.read_text().lstrip().startswith("{"):
            shutil.copyfile(src, out / ("npm-" + name + ".cdx.json"))
        execute([NODEBIN / "cyclonedx-npm", "--output-format", "JSON", "--spec-version", "1.6",
                 "--output-reproducible", "--output-file", out / ("cyclonedx-npm-" + name + ".cdx.json"), *extra],
                out, "cyclonedx-npm-" + name, cwd=project)
    bundle = WORK / "npm-bundle"
    bundle.mkdir(exist_ok=True)
    execute([NODEBIN / "esbuild", "index.js", "--bundle", "--platform=node", "--minify",
             "--legal-comments=none", "--outfile=" + str(bundle / "app.js"),
             "--metafile=" + str(out / "esbuild-metafile.json")], out, "bundle", cwd=project, required=True)
    execute(["node", bundle / "app.js"], out, "bundle-smoke", required=True)
    save(out / "bundle-manifest.json", {"artifact": str(bundle / "app.js"), "sha256": sha(bundle / "app.js"),
        "metafile_sha256": sha(out / "esbuild-metafile.json"),
        "note": "Controlled derived artifact, not an independent real application; original npm package versions unchanged"})
    snapshot(project, out, ["package.json", "package-lock.json", "index.js"])
    source = WORK / "npm-source"
    source.mkdir(exist_ok=True)
    for name in ["package.json", "package-lock.json", "index.js"]:
        shutil.copyfile(project / name, source / name)


JAVA_POM = '''<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
<groupId>org.example</groupId><artifactId>sbom-shade-probe</artifactId><version>1.0.0</version>
<properties><maven.compiler.source>8</maven.compiler.source><maven.compiler.target>8</maven.compiler.target></properties>
<dependencies>
 <dependency><groupId>org.apache.commons</groupId><artifactId>commons-compress</artifactId><version>1.20</version></dependency>
 <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version><scope>test</scope></dependency>
</dependencies>
<build><plugins><plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-shade-plugin</artifactId><version>3.6.1</version>
<executions><execution><phase>package</phase><goals><goal>shade</goal></goals><configuration>
<createDependencyReducedPom>false</createDependencyReducedPom>
<transformers><transformer implementation="org.apache.maven.plugins.shade.resource.ManifestResourceTransformer"><mainClass>org.example.App</mainClass></transformer></transformers>
</configuration></execution></executions></plugin></plugins></build></project>
'''


def java_probe():
    project = WORK / "java-build"
    out = OUT / "java-shade"
    write(project / "pom.xml", JAVA_POM)
    write(project / "src/main/java/org/example/App.java", '''package org.example;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;
public class App { public static void main(String[] args) {
 System.out.println(new ArchiveStreamFactory().getEntryEncoding());
} }
''')
    image = "maven:3.9.9-eclipse-temurin-17"
    image_meta = json.loads(subprocess.check_output(["docker", "image", "inspect", image], text=True))[0]
    image = image_meta["Id"]
    save(out / "image.json", dict(id=image, repo_digests=image_meta.get("RepoDigests")))
    m2 = WORK / "maven-cache"
    m2.mkdir(exist_ok=True)
    cmd = ["docker", "run", "--rm", "--cap-drop=ALL", "--security-opt=no-new-privileges",
           "--memory=2g", "--cpus=2", "--user", f"{os.getuid()}:{os.getgid()}",
           "-e", "MAVEN_CONFIG=/tmp/maven", "-v", f"{project}:/project", "-v", f"{m2}:/m2",
           "-w", "/project", image, "mvn", "-B", "-Dmaven.repo.local=/m2", "-Duser.home=/tmp",
           "-DskipTests", "package", "dependency:tree", "-DoutputType=json", "-DoutputFile=dependency-tree.json",
           "org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom", "-DoutputFormat=json", "-DincludeTestScope=false"]
    execute(cmd, out, "maven-build", timeout=900, required=True)
    shutil.copyfile(project / "dependency-tree.json", out / "dependency-tree.json")
    shutil.copyfile(project / "target/bom.json", out / "cyclonedx-maven.cdx.json")
    artifact = project / "target/sbom-shade-probe-1.0.0.jar"
    original_dir, stripped_dir = WORK / "java-shaded", WORK / "java-no-metadata"
    original_dir.mkdir(exist_ok=True)
    stripped_dir.mkdir(exist_ok=True)
    shutil.copyfile(artifact, original_dir / "app.jar")
    removed = []
    with zipfile.ZipFile(artifact) as source, zipfile.ZipFile(stripped_dir / "app.jar", "w", zipfile.ZIP_DEFLATED) as dest:
        original_classes, stripped_classes = {}, {}
        for member in source.infolist():
            if member.filename.startswith("META-INF/"):
                removed.append(member.filename)
                continue
            data = source.read(member.filename)
            dest.writestr(member.filename, data)
            if member.filename.endswith(".class"):
                stripped_classes[member.filename] = hashlib.sha256(data).hexdigest()
        original_classes = {m.filename: hashlib.sha256(source.read(m.filename)).hexdigest()
                            for m in source.infolist() if m.filename.endswith(".class")}
    assert original_classes == stripped_classes
    save(out / "artifact-control.json", dict(original_sha256=sha(artifact), stripped_sha256=sha(stripped_dir / "app.jar"),
         original_classes=original_classes, classes_unchanged=True, removed_metadata=removed,
         note="Controlled metadata-removal variant, not a claim that this exact artifact was published upstream"))
    for label, artifact_dir in [("original", original_dir), ("no-metadata", stripped_dir)]:
        execute(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop=ALL",
                 "-v", f"{artifact_dir}:/artifact:ro", image, "java", "-cp", "/artifact/app.jar", "org.example.App"],
                out, label + "-smoke", required=True)
    snapshot(project, out, ["pom.xml", "src/main/java/org/example/App.java"])
    upstream = WORK / "jbomaudit/samples/org.opendaylight.aaa/aaa-cli-jar/0.15.2"
    published = WORK / "java-jbomaudit"
    published.mkdir(exist_ok=True)
    evidence = OUT / "java-jbomaudit"
    evidence.mkdir(exist_ok=True)
    for path in upstream.iterdir():
        if path.suffix == ".jar":
            shutil.copyfile(path, published / path.name)
        else:
            shutil.copyfile(path, evidence / ("author-" + path.name))
    save(evidence / "acquisition.json", dict(url="https://github.com/code-genome/jbomaudit",
        commit=subprocess.check_output(["git", "-C", str(WORK / "jbomaudit"), "rev-parse", "HEAD"], text=True).strip(),
        files={p.name: sha(p) for p in upstream.iterdir() if p.is_file()},
        note="Published paper sample, author SBOM not exposed to archive scanners"))


def go_env():
    return dict(PATH=str(TOOLS / "go/bin") + os.pathsep + os.environ["PATH"],
                GOPATH=str(WORK / "gopath"), GOCACHE=str(WORK / "gocache"), GOTOOLCHAIN="local", CGO_ENABLED="0")


def go_probe():
    project = WORK / "go-build"
    out = OUT / "go-build"
    write(project / "go.mod", '''module example.org/sbom-build-probe

go 1.23

require (
 golang.org/x/text v0.3.0
 golang.org/x/crypto v0.17.0
 gopkg.in/yaml.v2 v2.2.8
)
replace golang.org/x/text v0.3.0 => golang.org/x/text v0.3.8
''')
    write(project / "main.go", '''package main
import ("fmt"; "golang.org/x/text/unicode/bidi")
func main() { fmt.Println(bidi.ReverseString("SBOM")) }
''')
    write(project / "windows.go", '''//go:build windows
package main
import _ "golang.org/x/crypto/ssh"
''')
    write(project / "main_test.go", '''package main
import ("testing"; "gopkg.in/yaml.v2")
func TestYAML(t *testing.T) { _, err := yaml.Marshal(map[string]string{"a":"b"}); if err != nil { t.Fatal(err) } }
''')
    env = go_env()
    execute(["go", "mod", "tidy"], out, "go-tidy", cwd=project, env=env, required=True)
    execute(["go", "list", "-m", "-json", "all"], out, "go-modules", cwd=project, env=env, required=True)
    execute(["go", "list", "-deps", "-json", "."], out, "go-linux-packages", cwd=project, env={**env, "GOOS":"linux", "GOARCH":"amd64"}, required=True)
    binary = WORK / "go-binary"
    binary.mkdir(exist_ok=True)
    execute(["go", "build", "-trimpath", "-ldflags=-s -w", "-o", binary / "app", "."],
            out, "go-build", cwd=project, env={**env, "GOOS":"linux", "GOARCH":"amd64"}, required=True)
    execute([binary / "app"], out, "go-smoke", required=True)
    execute(["go", "version", "-m", binary / "app"], out, "go-buildinfo", env=env, required=True)
    for mode in ["mod", "app"]:
        execute([TOOLS / "cyclonedx-gomod", mode, "-json", "-std", "-noserial", "-notimestamp",
                 "-output", out / ("cyclonedx-" + mode + ".cdx.json"), project],
                out, "cyclonedx-" + mode, cwd=project, env={**env, "GOOS":"linux", "GOARCH":"amd64"})
    execute([TOOLS / "cyclonedx-gomod", "bin", "-json", "-std", "-output", out / "cyclonedx-bin.cdx.json", binary / "app"],
            out, "cyclonedx-bin", env=env)
    snapshot(project, out, ["*.go", "go.mod", "go.sum"])
    save(out / "artifact.json", dict(sha256=sha(binary / "app"), GOOS="linux", GOARCH="amd64", CGO_ENABLED="0"))


def rust_env():
    return dict(PATH=str(TOOLS / "rust/bin") + os.pathsep + str(TOOLS) + os.pathsep + os.environ["PATH"],
                CARGO_HOME=str(WORK / "cargo-home"), CARGO_TARGET_DIR=str(WORK / "rust-target"))


def rust_probe():
    project = WORK / "rust-build"
    out = OUT / "rust-build"
    write(project / "Cargo.toml", '''[package]
name = "sbom-build-probe"
version = "1.0.0"
edition = "2021"

[dependencies]
regex_alias = { package = "regex", version = "=1.5.4" }
smallvec = { version = "=1.6.0", optional = true }

[target.'cfg(windows)'.dependencies]
time = "=0.1.45"

[dev-dependencies]
yaml-rust = "=0.4.5"
''')
    write(project / "src/main.rs", '''fn main() {
    let matcher = regex_alias::Regex::new("^SBOM$").unwrap();
    println!("{}", matcher.is_match("SBOM"));
}
''')
    env = rust_env()
    execute(["rustc", "--version", "--verbose"], out, "rustc-version", env=env, required=True)
    execute(["cargo", "--version"], out, "cargo-version", env=env, required=True)
    execute(["cargo", "generate-lockfile"], out, "cargo-lock", cwd=project, env=env, required=True)
    execute(["cargo", "metadata", "--format-version=1", "--filter-platform=x86_64-unknown-linux-gnu"],
            out, "cargo-metadata", cwd=project, env=env, required=True)
    execute(["cargo", "tree", "--target=x86_64-unknown-linux-gnu", "--edges=normal,build", "--prefix=none", "--format={p}"],
            out, "cargo-tree-production", cwd=project, env=env, required=True)
    execute(["cargo", "build", "--release", "--message-format=json"],
            out, "cargo-build", cwd=project, env=env, timeout=900, required=True)
    plain = WORK / "rust-binary"
    auditable = WORK / "rust-auditable"
    plain.mkdir(exist_ok=True)
    auditable.mkdir(exist_ok=True)
    shutil.copy2(WORK / "rust-target/release/sbom-build-probe", plain / "app")
    execute([plain / "app"], out, "rust-smoke", required=True)
    # Separate target dir ensures a real recompile with the auditable wrapper.
    execute(["cargo", "auditable", "build", "--release", "--message-format=json"],
            out, "cargo-auditable-build", cwd=project, env={**env, "CARGO_TARGET_DIR":str(WORK / "rust-auditable-target")},
            timeout=900, required=True)
    shutil.copy2(WORK / "rust-auditable-target/release/sbom-build-probe", auditable / "app")
    execute([auditable / "app"], out, "rust-auditable-smoke", required=True)
    for mode, extra in [("target", []), ("all-targets", ["--target=all", "--all-features"])]:
        execute([TOOLS / "cargo-cyclonedx", "cyclonedx", "--format=json", "--spec-version=1.6", *extra],
                out, "cargo-cyclonedx-" + mode, cwd=project, env=env)
        for generated in project.glob("*.cdx.json"):
            shutil.copyfile(generated, out / ("cyclonedx-" + mode + ".cdx.json"))
        # cargo-cyclonedx default filename is bom.json on some releases.
        if (project / "bom.json").exists():
            shutil.copyfile(project / "bom.json", out / ("cyclonedx-" + mode + ".cdx.json"))
    snapshot(project, out, ["Cargo.toml", "Cargo.lock", "src/main.rs"])
    save(out / "artifact.json", dict(plain_sha256=sha(plain / "app"), auditable_sha256=sha(auditable / "app"),
        target="x86_64-unknown-linux-gnu", feature_selection="default", command="cargo build --release"))


def scan_one(item):
    label, directory, ecosystem = item
    source = WORK / directory
    out = OUT / "scans" / label
    if not source.exists():
        return dict(case=label, status="NOT_BUILT")
    results = {}
    results["syft"] = execute([TOOLS / "syft", "scan", "dir:" + str(source),
        "-o", "cyclonedx-json=" + str(out / "syft.cdx.json"),
        "-o", "syft-json=" + str(out / "syft.native.json")], out, "syft", timeout=240)
    results["trivy"] = execute([TOOLS / "trivy", "fs", "--offline-scan", "--skip-db-update", "--skip-java-db-update",
        "--disable-telemetry", "--skip-version-check", "--parallel", "1", "--format", "cyclonedx",
        "--output", out / "trivy.cdx.json", source], out, "trivy", timeout=240)
    if ecosystem:
        results["cdxgen"] = execute([NODEBIN / "cdxgen", "-t", ecosystem, "--no-install-deps", "--no-validate",
            "--spec-version", "1.6", "-o", out / "cdxgen.cdx.json", source], out, "cdxgen", timeout=300,
            env={"FETCH_LICENSE": "false", "CDXGEN_TEMP_DIR": str(WORK / "cdxgen-temp"), **go_env()})
    return dict(case=label, tools={key: value["exit_code"] for key, value in results.items()})


def scans():
    cases = [("npm-source", "npm-source", "js"), ("npm-installed", "npm-alias", "js"),
             ("npm-bundle", "npm-bundle", "js"), ("java-shaded", "java-shaded", "jar"),
             ("java-no-metadata", "java-no-metadata", "jar"), ("java-jbomaudit", "java-jbomaudit", "jar"),
             ("go-source", "go-build", "go"), ("go-binary", "go-binary", "go"),
             ("rust-source", "rust-build", "rust"), ("rust-binary", "rust-binary", "rust"),
             ("rust-auditable", "rust-auditable", "rust")]
    with ThreadPoolExecutor(3) as executor:
        results = list(executor.map(scan_one, cases))
    save(OUT / "scan-summary.json", results)


def versions():
    out = OUT / "versions"
    for command, label in [(["node", "--version"], "node"), (["npm", "--version"], "npm"),
                           ([TOOLS / "syft", "version"], "syft"), ([TOOLS / "trivy", "--version"], "trivy"),
                           ([NODEBIN / "cdxgen", "--version"], "cdxgen"), ([NODEBIN / "cyclonedx-npm", "--version"], "cyclonedx-npm"),
                           ([TOOLS / "go/bin/go", "version"], "go"), ([TOOLS / "osv-scanner", "--version"], "osv-scanner"),
                           ([TOOLS / "cargo-cyclonedx", "cyclonedx", "--version"], "cargo-cyclonedx")]:
        execute(command, out, label, timeout=45)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["npm", "java", "go", "rust", "scan", "versions", "all"])
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    frozen = OUT / "executed-source" / (args.phase + "-" + str(time.time_ns()) + ".py")
    frozen.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(Path(__file__), frozen)
    save(OUT / ("phase-" + args.phase + ".json"), dict(script_sha256=sha(Path(__file__)),
         started_at=datetime.now(timezone.utc).isoformat(), phase=args.phase,
         kind="Exploratory mechanism probes, not prevalence or novelty estimates"))
    if args.phase == "all":
        versions()
        for name, function in [("npm", npm_probe), ("java", java_probe), ("go", go_probe), ("rust", rust_probe)]:
            try:
                function()
            except Exception as exc:
                save(OUT / (name + "-failure.json"), {"error": str(exc)})
        scans()
    else:
        {"npm": npm_probe, "java": java_probe, "go": go_probe, "rust": rust_probe, "scan": scans, "versions": versions}[args.phase]()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Summarize observed inventories and validate mechanism controls, without repair labels."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "runs/cross-ecosystem-probe-v1"
WORK = ROOT / "research/.work/cross-ecosystem-probe-v1"


def read(path):
    return json.loads(path.read_text())


def save(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def components(document):
    def walk(component):
        yield component
        for child in component.get("components", []):
            yield from walk(child)
    for component in document.get("components", []):
        yield from walk(component)


def versions(path, name):
    return sorted({c.get("version") for c in components(read(path)) if c.get("name") == name and c.get("version")})


def consumer_vulns(case, package):
    data = read(OUT / "consumers" / case / "osv.stdout")
    return [v for result in data.get("results", []) for p in result.get("packages", [])
            if p["package"]["name"] == package for v in p.get("vulnerabilities", [])]


def main():
    documents = []
    schema_results = []
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    import jsonschema
    from referencing import Registry, Resource
    schemas = {p.name: read(p) for p in (ROOT / "research/schemas").glob("*.schema.json")}
    resources = []
    for name, schema in schemas.items():
        resource = Resource.from_contents(schema)
        for uri in [schema["$id"], "http://cyclonedx.org/schema/" + name, "https://cyclonedx.org/schema/" + name]:
            resources.append((uri, resource))
    registry = Registry().with_resources(resources)
    for path in sorted(OUT.rglob("*.cdx.json")):
        if "attempts" in path.parts:
            continue
        data = read(path)
        cs = list(components(data))
        identities = sorted({(c.get("purl"), c.get("name"), c.get("version"))
                             for c in cs if c.get("purl")})
        documents.append(dict(path=str(path.relative_to(OUT)), sha256=sha(path), spec_version=data.get("specVersion"),
            component_entries=len(cs), unique_purl_entries=len(identities),
            identities=[dict(purl=p, name=n, version=v) for p,n,v in identities],
            declared_edge_entries=sum(len(d.get("dependsOn", [])) for d in data.get("dependencies", []))))
        filename = "bom-" + str(data.get("specVersion")) + ".schema.json"
        if filename not in schemas:
            schema_results.append(dict(path=str(path.relative_to(OUT)), status="SCHEMA_NOT_CACHED"))
            continue
        schema = schemas[filename]
        errors = list(jsonschema.Draft7Validator(schema, registry=registry).iter_errors(data))
        schema_results.append(dict(path=str(path.relative_to(OUT)), status="VALID" if not errors else "INVALID",
            errors=[dict(path=list(e.path), message=e.message) for e in errors[:10]]))
    save(OUT / "inventory-summary.json", dict(documents=documents,
         note="Counts describe documents and stages. No pooled precision/recall or runtime vulnerability ground truth."))
    save(OUT / "schema-validation.json", schema_results)

    checks = {}
    checks["go_control_same_native_resolution"] = read(OUT / "mechanism-controls/go-inactive-replace-control.json")["same_native_resolved_identities"]
    checks["go_default_source_disagrees_with_binary_version"] = (
        versions(OUT / "scans/go-source/syft.cdx.json", "golang.org/x/text") == ["v0.3.8"] and
        versions(OUT / "scans/go-binary/syft.cdx.json", "golang.org/x/text") == ["v0.14.0"])
    checks["go_control_and_native_mode_agree"] = (
        versions(OUT / "scans/go-no-inactive-replace/syft.cdx.json", "golang.org/x/text") == ["v0.14.0"] and
        versions(OUT / "mechanism-controls/go-syft-packages-lib.cdx.json", "golang.org/x/text") == ["v0.14.0"])
    checks["rust_control_same_lock_and_production_closure"] = all(read(OUT / "mechanism-controls/rust-alias-control.json")[k]
        for k in ["same_production_tree_identities", "identical_cargo_lock"])
    checks["rust_alias_changes_trivy_inventory"] = (
        versions(OUT / "scans/rust-source/trivy.cdx.json", "regex") == [] and
        versions(OUT / "scans/rust-no-alias/trivy.cdx.json", "regex") == ["1.5.4"])
    checks["rust_native_and_auditable_recognize_regex"] = all(
        versions(OUT / p, "regex") == ["1.5.4"] for p in ["rust-build/cyclonedx-target.cdx.json", "scans/rust-auditable/syft.cdx.json"])
    checks["rust_advisory_CVE_2022_24713_returns_in_control"] = (
        not consumer_vulns("rust-source-trivy", "regex") and
        any("CVE-2022-24713" in v.get("aliases", []) for v in consumer_vulns("rust-no-alias-trivy", "regex")))
    checks["graph_removal_does_not_change_this_consumer"] = read(OUT / "mechanism-controls/graph-consumer-result.json")["identical_package_advisory_sets"]
    checks["go123_native_std_has_no_OSV_match"] = not consumer_vulns("go123-native", "std")
    stdlib = consumer_vulns("go123-syft", "stdlib")
    adapted = consumer_vulns("go123-adapted", "stdlib")
    checks["go123_adapter_recovers_same_advisory_records_as_syft"] = bool(stdlib) and {v["id"] for v in stdlib} == {v["id"] for v in adapted}
    original = WORK / "java-shaded/app.jar"
    derived = WORK / "java-no-metadata/app.jar"
    def class_hashes(path):
        with zipfile.ZipFile(path) as archive:
            return {name: hashlib.sha256(archive.read(name)).hexdigest() for name in archive.namelist() if name.endswith(".class")}
    checks["java_metadata_removal_preserves_every_class_byte"] = class_hashes(original) == class_hashes(derived)
    minimized = read(OUT / "java-minimized/artifact.json")
    checks["java_minimized_has_only_application_class"] = minimized["all_classes"] == ["org/example/App.class"]
    checks["java_minimized_still_matches_package_advisories"] = bool(consumer_vulns("java-minimized-native", "org.apache.commons:commons-compress"))
    paper_artifact = WORK / "java-jbomaudit/aaa-cli-jar-0.15.2.jar"
    with zipfile.ZipFile(paper_artifact) as archive:
        names = archive.namelist()
        class_absences = {name: name not in names for name in [
            "org/apache/commons/text/StringSubstitutor.class", "org/apache/commons/text/lookup/StringLookupFactory.class"]}
    matched = read(OUT / "java-jbomaudit/commons-text-class-evidence.json")["exact_class_matches"]
    save(OUT / "java-jbomaudit/commons-text-symbol-observation.json", dict(absent_classes=class_absences,
        matched_class_count=len(matched), matched_artifact_sha256=sha(paper_artifact),
        advisory_url="https://commons.apache.org/proper/commons-text/security.html",
        conclusion="Classes absent from this JAR. External classpath, runtime loading and whole-application exploitability were not assessed."))
    checks["paper_java_has_21_exact_upstream_class_matches"] = len(matched) == 21
    checks["paper_java_lacks_two_advisory_related_classes"] = all(class_absences.values())
    input_checks = []
    for path in OUT.rglob("input-manifest.json"):
        data = read(path)
        base = Path(data["source"])
        for relative, expected in data["files"].items():
            if not (base / relative).exists() or sha(base / relative) != expected:
                input_checks.append(str(path.relative_to(OUT)) + ":" + relative)
    checks["captured_inputs_unchanged"] = not input_checks
    consumers = read(OUT / "consumer-summary.json")
    checks["all_consumers_bound_to_unchanged_SBOM_inputs"] = all(sha(OUT / c["sbom"]) == c["sbom_sha256"] for c in consumers if "sbom" in c)
    bindings = read(OUT / "mechanism-controls/bundle-input-hashes.json")
    checks["bundle_input_hashes_unchanged"] = all(sha(WORK / "npm-alias" / name) == digest for name,digest in bindings["inputs"].items())
    checks["bundle_only_uses_vulnerable_alias_not_fixed_alias"] = any("lodash-vulnerable" in name for name in bindings["inputs"]) and not any("lodash-fixed" in name for name in bindings["inputs"])
    checks["npm_installed_mode_recognizes_both_real_lodash_versions"] = versions(OUT / "scans/npm-installed/syft-installed.cdx.json", "lodash") == ["4.17.20", "4.17.21"]
    summary = dict(generated_at=datetime.now(timezone.utc).isoformat(),
        kind="Exploratory evidence, purposive mechanisms; not population estimates or a novel recovery evaluation",
        document_count=len(documents), checks_passed=sum(checks.values()), checks_total=len(checks),
        go_stdlib_advisory_record_count=len(stdlib),
        rust_regex_advisory_ids=[v["id"] for v in consumer_vulns("rust-native", "regex")],
        rust_regex_unique_CVE_ids=sorted({a for v in consumer_vulns("rust-native", "regex") for a in v.get("aliases", []) if a.startswith("CVE-")}),
        schema_statuses={s:sum(r["status"]==s for r in schema_results) for s in sorted({r["status"] for r in schema_results})},
        input_mismatches=input_checks)
    save(OUT / "summary.json", summary)
    save(OUT / "validation.json", dict(checks=checks, all_passed=all(checks.values()),
        note="Integration assertions over local evidence. Not proof of input truth or runtime safety; not a per-change certificate/checker."))
    print(json.dumps(summary, indent=2))
    if not all(checks.values()):
        raise SystemExit("FAILED: " + ", ".join(k for k,v in checks.items() if not v))


if __name__ == "__main__":
    main()

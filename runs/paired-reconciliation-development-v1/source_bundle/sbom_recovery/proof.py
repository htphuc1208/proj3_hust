"""Resolve explicit evidence selectors independently of the gold emitter.

JSON/TOML selectors use RFC 6901. Computed values declare a bounded operation;
raw_value in a claim is never trusted as the proof. No project code is executed.
"""
from __future__ import annotations

import ast
import configparser
import email
import hashlib
import json
import re
import tarfile
import tomllib
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Literal

from packageurl import PackageURL
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from pydantic import BaseModel, ConfigDict

from .gold_contracts import CaseManifest, contained, fingerprint


class Selector(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    format: Literal["json", "toml", "ini", "setup", "pom", "wheel", "npm-tar", "jar"]
    pointer: str = ""
    operation: Literal["literal", "python-requirement", "npm-requirement", "poetry-requirement",
                       "maven-name", "maven-requirement", "node-name", "node-version", "node-purl",
                       "edge", "python-name", "checksum", "jar-name"] = "literal"
    member: str | None = None


def pointer(*tokens):
    return "".join("/" + str(t).replace("~", "~0").replace("/", "~1") for t in tokens)


def tokens(path):
    if path == "": return []
    if not path.startswith("/") or re.search(r"~(?![01])", path):
        raise ValueError("Invalid RFC 6901 pointer")
    return [t.replace("~1", "/").replace("~0", "~") for t in path[1:].split("/")]


def select(value, path):
    for token in tokens(path):
        if isinstance(value, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", token): raise ValueError("Invalid array index")
            value = value[int(token)]
        elif isinstance(value, dict): value = value[token]
        else: raise ValueError("Selector traverses a scalar")
    return value


def locator(format, path="", operation="literal", member=None):
    spec = Selector(format=format, pointer=path, operation=operation, member=member)
    tokens(path)
    return "proof-v1:" + spec.model_dump_json(exclude_none=True)


def identity(ecosystem, name, version=None):
    namespace = None
    if ecosystem == "maven": namespace, name = name.split(":", 1)
    elif ecosystem == "npm" and name.startswith("@"): namespace, name = name.split("/", 1)
    elif ecosystem == "pypi": name = canonicalize_name(name)
    return PackageURL(type=ecosystem, namespace=namespace, name=name, version=version).to_string()


def pom_document(text):
    tree = ET.fromstring(text)
    for element in tree.iter(): element.tag = element.tag.split("}")[-1]
    def fields(element):
        return {k:element.findtext(k) for k in ("groupId", "artifactId", "version", "scope")}
    result = fields(tree)
    parent = tree.find("parent")
    result["parent"] = fields(parent) if parent is not None else {}
    result["dependencies"] = [fields(d) for d in tree.findall("dependencies/dependency")]
    return result


def setup_document(text):
    """Read top-level literal assignments/keywords; dynamic expressions stay unavailable."""
    variables = {}; calls = []
    for node in ast.parse(text).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try: variables[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError): variables.pop(node.targets[0].id, None)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == "setup":
            keywords = {}
            for kw in node.value.keywords:
                try: keywords[kw.arg] = variables[kw.value.id] if isinstance(kw.value, ast.Name) else ast.literal_eval(kw.value)
                except (KeyError, TypeError, ValueError): continue
            calls.append(keywords)
    if len(calls) != 1: raise ValueError("Expected one top-level setup declaration")
    return {"setup":calls[0]}


class ProofReader:
    def __init__(self, case_path, allowed_only=False):
        self.root = Path(case_path).resolve().parent
        self.case = CaseManifest.model_validate_json(Path(case_path).read_text())
        self.allowed_only = allowed_only
        self.cache = {}

    def load(self, source, spec):
        if source not in self.case.files or (self.allowed_only and source not in self.case.allowed_evidence):
            raise ValueError("Evidence not permitted")
        item = self.case.files[source]
        path = contained(self.root, item.path)
        key = (source, spec.format, spec.member)
        if key in self.cache: return self.cache[key]
        with path.open("rb") as stream: actual_hash = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual_hash != item.sha256: raise ValueError("Changed evidence bytes")
        if spec.format == "json": data = json.loads(path.read_text())
        elif spec.format == "toml": data = tomllib.loads(path.read_text())
        elif spec.format == "ini":
            cfg = configparser.ConfigParser(interpolation=None); cfg.read_string(path.read_text())
            data = {section:dict(cfg[section]) for section in cfg.sections()}
            if "install_requires" in data.get("options", {}):
                data["options"]["install_requires"] = [x.strip() for x in data["options"]["install_requires"].splitlines() if x.strip()]
        elif spec.format == "setup": data = setup_document(path.read_text())
        elif spec.format == "pom": data = pom_document(path.read_text())
        else:
            if not spec.member: raise ValueError("Archive member required")
            if spec.format in {"wheel", "jar"}:
                with zipfile.ZipFile(path) as archive:
                    matches = [i for i in archive.infolist() if i.filename == spec.member]
                    if len(matches) != 1 or matches[0].file_size > 2_000_000: raise ValueError("Ambiguous or oversized archive member")
                    raw = archive.read(matches[0])
                if spec.format == "wheel":
                    meta = email.message_from_bytes(raw)
                    for field in ("Name", "Version", "License-Expression"):
                        if len(meta.get_all(field, [])) > 1: raise ValueError("Duplicate scalar METADATA field")
                    data = dict(meta.items())
                else:
                    data = dict(line.split("=", 1) for line in raw.decode().splitlines() if "=" in line and not line.startswith("#"))
            else:
                with tarfile.open(path) as archive:
                    members = [m for m in archive.getmembers() if m.name == spec.member]
                    if len(members) != 1 or not members[0].isfile() or members[0].size > 2_000_000:
                        raise ValueError("Ambiguous or oversized tar member")
                    data = json.load(archive.extractfile(members[0]))
        self.cache[key] = data
        return data

    def inspect(self, claim, evidence):
        if claim.status == "verified_absent":
            raise ValueError("Positive selectors cannot prove absence; independent bounded adjudication required")
        if claim.case_id != self.case.case_id or claim.target_id != self.case.target:
            raise ValueError("Claim case/target mismatch")
        if not evidence.locator.startswith("proof-v1:"):
            raise ValueError("Legacy descriptive locator; no executable selector")
        spec = Selector.model_validate_json(evidence.locator[len("proof-v1:"):])
        item = self.case.files[evidence.source_id]
        if evidence.artifact_sha256 != item.sha256: raise ValueError("Evidence hash mismatch")
        document = self.load(evidence.source_id, spec)
        raw = select(document, spec.pointer)
        op = spec.operation; result = raw; scope = None; condition = None
        parts = tokens(spec.pointer)
        if claim.layer == "G2_resolved" and not (op.startswith("node-") or op == "edge"):
            raise ValueError("Resolved claims require a native node/edge derivation")
        required = {"python-requirement":"depends_on", "npm-requirement":"depends_on", "poetry-requirement":"depends_on",
                    "maven-name":"name", "maven-requirement":"depends_on", "jar-name":"name",
                    "python-name":"name", "checksum":"checksum"}
        if op in required and claim.predicate != required[op]: raise ValueError("Derivation predicate mismatch")
        if op == "literal":
            fields = {"Name":"name", "name":"name", "Version":"version", "version":"version",
                      "license":"licenseDeclared", "License-Expression":"licenseDeclared"}
            if not parts or fields.get(parts[-1]) != claim.predicate: raise ValueError("Literal field/predicate mismatch")
            if claim.layer == "G1_source":
                allowed = {
                    "json": {("name",),("version",),("license",)} if item.kind=="manifest" else {("source_model","name"),("source_model","version")},
                    "toml": {("project",k) for k in ("name","version","license")} | {("tool","poetry",k) for k in ("name","version","license")},
                    "ini": {("metadata","name"),("metadata","version")},
                    "setup": {("setup","name"),("setup","version")},
                    "pom": {("version",),("parent","version")},
                }
                if tuple(parts) not in allowed.get(spec.format,set()):
                    raise ValueError("Literal does not identify root source metadata")
            elif claim.layer == "G3_artifact":
                allowed = {"wheel":{("Name",),("Version",),("License-Expression",)},
                           "npm-tar":{("name",),("version",),("license",)},"jar":{("version",)}}
                if tuple(parts) not in allowed.get(spec.format,set()): raise ValueError("Invalid artifact metadata field")
        if op.startswith("node-") or op == "edge":
            if len(parts) != 2 or parts[0] != ("edges" if op=="edge" else "nodes"):
                raise ValueError("Invalid native graph selector")
        if op == "python-requirement":
            valid = ((spec.format=="toml" and ((parts[:2]==["project","dependencies"] and len(parts)==3) or
                     (parts[:2]==["project","optional-dependencies"] and len(parts)==4))) or
                     (spec.format=="ini" and parts[:2]==["options","install_requires"] and len(parts)==3) or
                     (spec.format=="setup" and parts[:2]==["setup","install_requires"] and len(parts)==3))
            if not valid: raise ValueError("Selector is not a declared Python dependency")
        if op == "npm-requirement" and (spec.format!="json" or len(parts)!=2 or parts[0] not in {
                "dependencies","devDependencies","optionalDependencies","peerDependencies"}):
            raise ValueError("Selector is not an npm dependency declaration")
        if op == "poetry-requirement" and (spec.format!="toml" or parts[:3]!=["tool","poetry","dependencies"] or len(parts)!=4):
            raise ValueError("Selector is not a Poetry dependency declaration")
        if op == "maven-name" and (spec.format!="pom" or parts): raise ValueError("Invalid Maven identity selector")
        if op == "maven-requirement" and (spec.format!="pom" or len(parts)!=2 or parts[0]!="dependencies"):
            raise ValueError("Selector is not a Maven dependency declaration")
        if op == "checksum" and (parts or spec.format not in {"wheel","jar","npm-tar"}):
            raise ValueError("Checksum must refer to whole artifact bytes")
        if op == "python-name" and (spec.format!="wheel" or parts!=["Name"]): raise ValueError("Invalid Python artifact name selector")
        if op == "jar-name" and (spec.format!="jar" or parts): raise ValueError("Invalid JAR identity selector")
        if op.startswith("node-") or op == "edge":
            if item.kind != "resolver" or claim.layer != "G2_resolved": raise ValueError("Native graph proof scope mismatch")
            for field in ("commit", "target", "environment"):
                if document[field] != getattr(self.case, field): raise ValueError("Native graph context mismatch")
            if document.get("status") != "COMPLETE" or self.case.resolution_status != "COMPLETE":
                raise ValueError("Incomplete native graph")
            if op == "edge":
                source, result = raw
                node = next(n for n in document["nodes"] if n["id"] == source)
                if not any(n["id"] == result for n in document["nodes"]): raise ValueError("Unknown edge endpoint")
                if claim.predicate != "depends_on": raise ValueError("Wrong edge predicate")
            else:
                node = raw; pred = op[len("node-"):]
                if claim.predicate != pred: raise ValueError("Wrong node predicate")
                result = identity(self.case.ecosystem, node["name"], node["version"]) if pred == "purl" else node[pred]
            if claim.instance_id != node["id"] or claim.subject != identity(self.case.ecosystem, node["name"], node["version"]):
                raise ValueError("Native instance/subject mismatch")
            scope = "runtime_production"
        elif op == "python-requirement":
            req = Requirement(raw)
            result = {"package":identity("pypi", req.name), "requirement":str(req.specifier), "extras":sorted(req.extras), "url":req.url}
            parts = tokens(spec.pointer)
            extra = parts[2] if parts[:2] == ["project", "optional-dependencies"] else None
            scope = "optional" if extra else "runtime_production"
            condition = "; ".join(x for x in [str(req.marker) if req.marker else None, "extra == " + repr(extra) if extra else None] if x) or None
        elif op in {"npm-requirement", "poetry-requirement"}:
            parts = tokens(spec.pointer); name = parts[-1]
            result = {"package":identity("npm" if op == "npm-requirement" else "pypi", name),
                      "requirement" if op == "npm-requirement" else "poetry_declaration":raw}
            scope = {"dependencies":"runtime_production", "devDependencies":"development",
                     "optionalDependencies":"optional", "peerDependencies":"optional"}.get(parts[0]) if op == "npm-requirement" else (
                         "optional" if isinstance(raw, dict) and raw.get("optional") else "runtime_production")
        elif op == "maven-name":
            result = (raw.get("groupId") or raw["parent"]["groupId"]) + ":" + raw["artifactId"]
        elif op == "maven-requirement":
            declared = raw.get("scope") or "compile"
            result = {"package":identity("maven", raw["groupId"]+":"+raw["artifactId"]),
                      "requirement":raw.get("version"), "maven_scope":declared}
            scope = {"test":"test", "provided":"build", "system":"build"}.get(declared, "runtime_production")
        elif op == "python-name": result = canonicalize_name(raw)
        elif op == "jar-name": result = raw["groupId"] + ":" + raw["artifactId"]
        elif op == "checksum": result = item.sha256
        if claim.layer == "G1_source":
            if item.kind not in {"manifest", "resolver"}: raise ValueError("Wrong source proof authority")
            if claim.instance_id != "root" or claim.subject != "urn:target:"+self.case.case_id+":"+self.case.target:
                raise ValueError("Source instance mismatch")
            scope = scope or "runtime_production"
        elif claim.layer == "G3_artifact":
            if item.kind != "artifact": raise ValueError("Wrong artifact authority")
            if spec.format == "wheel": name, version = document["Name"], document["Version"]
            elif spec.format == "npm-tar": name, version = document["name"], document["version"]
            elif spec.format == "jar": name, version = document["groupId"]+":"+document["artifactId"], document["version"]
            else: raise ValueError("Missing artifact metadata")
            if claim.subject != identity(self.case.ecosystem, name, version): raise ValueError("Artifact subject mismatch")
            instance = "artifact:"+evidence.source_id + (":"+spec.member if spec.format=="jar" else "")
            if claim.instance_id != instance: raise ValueError("Artifact instance mismatch")
            scope = "runtime_production"
        if scope is not None and claim.scope != scope: raise ValueError("Proof scope mismatch")
        if claim.condition != condition: raise ValueError("Proof condition mismatch")
        if fingerprint(result) != fingerprint(claim.object): raise ValueError("Evidence does not support value")
        return {"source_id":evidence.source_id, "path":item.path, "sha256":item.sha256,
                "selector":spec.model_dump(mode="json"), "raw_value":raw, "derived_value":result}

    def audit(self, ledger):
        if ledger.role != "gold": raise ValueError("Expected gold role for provenance audit")
        if ledger.case_manifest_sha256 != self.case.digest(): raise ValueError("Ledger binding mismatch")
        failures = []; checked = 0
        for claim in ledger.claims:
            if claim.status not in {"verified", "verified_absent"}: continue
            if not claim.evidence: failures.append({"claim_id":claim.claim_id, "error":"No evidence"})
            for evidence in claim.evidence:
                try: self.inspect(claim, evidence); checked += 1
                except (ValueError, KeyError, IndexError, TypeError, OSError) as exc:
                    failures.append({"claim_id":claim.claim_id, "locator":evidence.locator, "error":str(exc)})
        return {"status":"PASSED" if not failures else "FAILED", "checked_citations":checked, "failures":failures,
                "independence":"Separate selector/derivation implementation; shared source bytes and standards libraries", "human_review":"PENDING"}

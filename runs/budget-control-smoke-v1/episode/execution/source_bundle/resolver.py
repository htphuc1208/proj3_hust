#!/usr/bin/env python3
"""Context-Aware, Evidence-Guided SBOM Dependency Resolver.

Implements the formal architecture defined in ARCHITECTURE.md:
1. Environment-constrained dependency evaluation (PEP 508).
2. Multi-context epistemic modality (MUST, MAY, UNKNOWN) under unspecified environment.
3. Strict separation of G_obs, G_candidate, and G_reconstructed with CONTRADICTED_DECLARATION detection.
4. Downstream Vulnerability Recovery Rate (VRR) & OpenVEX-compliant reachability analysis.
"""
from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass, field, replace
import re
from urllib.parse import unquote
from packaging.utils import canonicalize_name
import json
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any

try:
    from packaging.markers import Marker
    from packaging.version import Version
    from packaging.specifiers import SpecifierSet
except ImportError:
    Marker = None
    Version = None
    SpecifierSet = None


@dataclass(frozen=True)
class TargetEnvironment:
    """Explicit runtime environment specification according to PEP 508."""
    os_name: str                  # e.g., 'posix', 'nt'
    sys_platform: str             # e.g., 'linux', 'win32', 'darwin'
    platform_machine: str         # e.g., 'x86_64', 'AMD64', 'arm64'
    python_version: str           # e.g., '3.10', '3.11'
    platform_system: str = "Linux"
    active_extras: Set[str] = field(default_factory=set)
    python_full_version: Optional[str] = None

    def to_marker_dict(self, extra: Optional[str] = None) -> Dict[str, str]:
        env_dict = {
            "os_name": self.os_name,
            "sys_platform": self.sys_platform,
            "platform_machine": self.platform_machine,
            "python_version": self.python_version,
            "python_full_version": self.python_full_version or self.python_version + ".0",
            "platform_system": self.platform_system,
            "implementation_name": "cpython",
            "extra": extra or "",
        }
        return env_dict


# Default canonical evaluation matrix when environment context is omitted
PLAUSIBLE_ENVIRONMENTS: List[TargetEnvironment] = [
    TargetEnvironment(os_name="posix", sys_platform="linux", platform_machine="x86_64", python_version="3.10", platform_system="Linux"),
    TargetEnvironment(os_name="posix", sys_platform="linux", platform_machine="x86_64", python_version="3.11", platform_system="Linux"),
    TargetEnvironment(os_name="posix", sys_platform="linux", platform_machine="x86_64", python_version="3.12", platform_system="Linux"),
    TargetEnvironment(os_name="nt", sys_platform="win32", platform_machine="AMD64", python_version="3.10", platform_system="Windows"),
    TargetEnvironment(os_name="nt", sys_platform="win32", platform_machine="AMD64", python_version="3.11", platform_system="Windows"),
    TargetEnvironment(os_name="posix", sys_platform="darwin", platform_machine="arm64", python_version="3.11", platform_system="Darwin"),
]


def evaluate_pep508_marker(marker_str: str, env: TargetEnvironment, extra: Optional[str] = None) -> Optional[bool]:
    """Evaluates a PEP 508 environment marker string against a TargetEnvironment."""
    if not marker_str or marker_str.strip() == "":
        return True
    if Marker is None:
        return None
    try:
        marker = Marker(marker_str)
        # Never inherit unobserved PEP 508 variables from the analyst's host.
        unknown = {"platform_release", "platform_version", "implementation_version", "platform_python_implementation"}
        if not env.python_full_version:
            unknown.add("python_full_version")
        if any(re.search(r"\b" + name + r"\b", str(marker)) for name in unknown):
            return None
        base_extra = extra or ""
        if marker.evaluate(env.to_marker_dict(extra=base_extra)):
            return True
        for act_extra in env.active_extras:
            if marker.evaluate(env.to_marker_dict(extra=act_extra)):
                return True
        return False
    except Exception:
        # On malformed marker, treat as unknown/unhandled
        return None


def normalize_purl(purl: str) -> str:
    """Normalizes PyPI PURLs for consistent graph alignment."""
    prefix = "pkg:pypi/"
    if not isinstance(purl, str) or not purl.startswith(prefix) or "@" not in purl:
        return purl
    name, version = purl[len(prefix):].split("?", 1)[0].split("#", 1)[0].rsplit("@", 1)
    name = canonicalize_name(unquote(name))
    version = unquote(version)
    return f"pkg:pypi/{name}@{version}"


@dataclass
class DependencyRequirement:
    """Representation of a declared requirement with optional PEP 508 marker."""
    target_purl: str
    marker: Optional[str] = None
    extra: Optional[str] = None
    specifier: Optional[str] = None
    requested_extras: Set[str] = field(default_factory=set)


@dataclass
class CandidateEdge:
    source_purl: str
    target_purl: str
    modality: str                  # 'MUST', 'MAY_ONLY', 'UNKNOWN'
    status: str                    # 'INFERRED', 'CONTRADICTED_DECLARATION', 'CONFIRMED', 'AMBIGUOUS_MATCH'
    evidence_source: str
    provenance_detail: str
    marker: Optional[str] = None
    valid_environments: List[str] = field(default_factory=list)
    candidate_refs: List[str] = field(default_factory=list)


@dataclass
class CandidateNode:
    purl: str
    status: str                    # 'INFERRED', 'CONFIRMED'
    evidence_source: str
    provenance_detail: str


class ContextAwareResolver:
    def __init__(self, metadata_provider):
        """
        metadata_provider: Object providing get_requirements(purl) -> List[DependencyRequirement]
        """
        self.provider = metadata_provider

    def resolve(
        self,
        sbom: Dict[str, Any],
        target_env: Optional[TargetEnvironment] = None,
        candidate_environments: Optional[List[TargetEnvironment]] = None,
    ) -> Dict[str, Any]:
        """
        Resolves SBOM dependency graph under specified environment or epistemic modalities.
        Preserves G_obs verbatim while creating G_candidate and G_reconstructed.
        """
        # 1. Parse G_obs (Verbatim immutable copy)
        g_obs_raw = deepcopy(sbom)
        root_comp = g_obs_raw.get("metadata", {}).get("component", {})
        components = [root_comp] + g_obs_raw.get("components", [])

        ref_to_purl: Dict[str, str] = {}
        purl_to_ref: Dict[str, str] = {}
        # Map package names to list of (ref, purl, version)
        pkg_name_to_components: Dict[str, List[Tuple[str, str, str]]] = defaultdict(list)
        for c in components:
            ref = c.get("bom-ref")
            purl = c.get("purl")
            ver = c.get("version", "")
            if ref and purl:
                norm = normalize_purl(purl)
                ref_to_purl[ref] = norm
                purl_to_ref[norm] = ref
                if norm.startswith("pkg:pypi/"):
                    pkg_raw = norm[len("pkg:pypi/"):].split("@")[0]
                    canon = pkg_raw.lower().replace("_", "-")
                    pkg_name_to_components[canon].append((ref, norm, ver))

        # Explicit dependencies dictionary from G_obs: ref -> set of dependsOn refs
        g_obs_deps: Dict[str, Set[str]] = {}
        explicitly_declared_refs: Set[str] = set()
        for d in g_obs_raw.get("dependencies", []):
            src_ref = d.get("ref")
            if src_ref:
                explicitly_declared_refs.add(src_ref)
                g_obs_deps[src_ref] = set(d.get("dependsOn", []))

        # Check for empty explicit declarations (dependsOn: [])
        empty_declared_refs = {
            r for r, children in g_obs_deps.items() if len(children) == 0
        }

        # Environments to consider
        eval_envs = [target_env] if target_env else (candidate_environments or PLAUSIBLE_ENVIRONMENTS)

        candidate_nodes: Dict[str, CandidateNode] = {}
        candidate_edges: List[CandidateEdge] = []
        contradictions: List[Dict[str, Any]] = []
        unresolved = []

        # Extras belong to distributions, not globally to every package in a venv.
        # Compute a monotone fixed point before evaluating edge modalities.
        requirements_cache = {}
        extras_by_env = []
        root_purl = normalize_purl(root_comp.get("purl", ""))
        for env in eval_envs:
            extras = defaultdict(set)
            extras[root_purl].update(canonicalize_name(x) for x in env.active_extras)
            pending = list(purl_to_ref)
            processed = {}
            while pending:
                parent = pending.pop(0)
                state = frozenset(extras[parent])
                if processed.get(parent) == state:
                    continue
                processed[parent] = state
                if parent not in requirements_cache:
                    requirements_cache[parent] = self.provider.get_requirements(parent)
                for req in requirements_cache[parent] or []:
                    local_env = replace(env, active_extras=set(state))
                    if req.extra and canonicalize_name(req.extra) not in state:
                        continue
                    if evaluate_pep508_marker(req.marker or "", local_env) is not True:
                        continue
                    target = normalize_purl(req.target_purl)
                    base = target[len("pkg:pypi/"):].split("@")[0]
                    matches = []
                    for _, p, v in pkg_name_to_components.get(base, []):
                        try:
                            if not req.specifier or SpecifierSet(req.specifier).contains(v, prereleases=True):
                                if "@" not in target or target == p:
                                    matches.append(p)
                        except Exception:
                            continue
                    if not matches and "@" in target:
                        matches = [target]
                    if len(matches) == 1:
                        child = matches[0]
                        before = set(extras[child])
                        extras[child].update(canonicalize_name(x) for x in req.requested_extras)
                        if child not in processed or before != extras[child]:
                            pending.append(child)
            extras_by_env.append(extras)

        # Queue for discovery: (purl, depth)
        queue = [(p, 0) for p in sorted(purl_to_ref.keys())]
        visited_purls: Set[str] = set()

        while queue:
            current_purl, depth = queue.pop(0)
            if current_purl in visited_purls or depth > 4:
                continue
            visited_purls.add(current_purl)

            # Retrieve evidence requirements from provider
            reqs = requirements_cache.get(current_purl)
            if current_purl not in requirements_cache:
                reqs = self.provider.get_requirements(current_purl)
            if reqs is None:
                unresolved.append({"parent": current_purl, "reason": "EVIDENCE_UNAVAILABLE"})
                continue

            current_ref = purl_to_ref.get(current_purl)

            # Check if G_obs declared dependsOn: [] for this component
            is_empty_declared = current_ref in empty_declared_refs

            for req in reqs:
                target_norm = normalize_purl(req.target_purl)
                target_base = target_norm[len("pkg:pypi/"):].split("@")[0].lower().replace("_", "-") if target_norm.startswith("pkg:pypi/") else target_norm

                # Candidate matching rule: C(u, r, E) = {v in V_obs : match(v, r, E)}
                matching_nodes: List[Tuple[str, str]] = []
                if target_norm in purl_to_ref:
                    matching_nodes.append((purl_to_ref[target_norm], target_norm))
                else:
                    candidates_pool = pkg_name_to_components.get(target_base, [])
                    for comp_ref, comp_purl, comp_ver in candidates_pool:
                        if req.specifier and SpecifierSet and comp_ver:
                            try:
                                if Version(comp_ver) in SpecifierSet(req.specifier):
                                    matching_nodes.append((comp_ref, comp_purl))
                            except Exception:
                                unresolved.append({"parent": current_purl, "reason": "INVALID_VERSION_OR_CONSTRAINT",
                                                   "constraint": req.specifier, "version": comp_ver})
                        else:
                            matching_nodes.append((comp_ref, comp_purl))

                # Modality calculation across eval_envs
                active_envs = []
                unknown_envs = []
                for env_index, env in enumerate(eval_envs):
                    local_extras = extras_by_env[env_index][current_purl]
                    local_env = replace(env, active_extras=local_extras)
                    if req.extra and canonicalize_name(req.extra) not in local_extras:
                        continue
                    activity = evaluate_pep508_marker(req.marker or "", local_env)
                    if activity is None:
                        unknown_envs.append(f"{env.sys_platform}_{env.python_version}")
                    if activity is True:
                        active_envs.append(f"{env.sys_platform}_{env.python_version}")

                if not active_envs and not unknown_envs:
                    # Inactive across all evaluated environments
                    continue

                if unknown_envs:
                    modality = "UNKNOWN"
                    unresolved.append({"parent": current_purl, "reason": "MARKER_CONTEXT_UNKNOWN", "marker": req.marker})
                elif target_env:
                    modality = "MUST"
                else:
                    if len(active_envs) == len(eval_envs):
                        modality = "MUST"
                    else:
                        modality = "MAY_ONLY"

                # Apply Decision B cardinality rules:
                if len(matching_nodes) == 1:
                    # |C| == 1: Unique valid match!
                    target_ref, resolved_target_purl = matching_nodes[0]
                    already_declared = current_ref and target_ref in g_obs_deps.get(current_ref, set())

                    if already_declared:
                        edge_status = "CONFIRMED"
                    elif is_empty_declared:
                        edge_status = "CONTRADICTED_DECLARATION"
                        contradictions.append({
                            "source": current_purl,
                            "contradicted_target": resolved_target_purl,
                            "declared_in_sbom": "dependsOn: []",
                            "evidence": self.provider.source_name,
                            "marker": req.marker,
                            "modality": modality,
                            "valid_environments": active_envs,
                            "policy": "Preserve G_obs; emit candidate repair with provenance"
                        })
                    else:
                        edge_status = "INFERRED"

                    candidate_edges.append(CandidateEdge(
                        source_purl=current_purl,
                        target_purl=resolved_target_purl,
                        modality=modality,
                        status=edge_status,
                        evidence_source=self.provider.source_name,
                        provenance_detail=f"PEP508 condition: {req.marker or 'unconditional'}",
                        marker=req.marker,
                        valid_environments=active_envs
                    ))

                elif len(matching_nodes) > 1:
                    # |C| > 1: Ambiguous match across multiple observed components!
                    candidate_edges.append(CandidateEdge(
                        source_purl=current_purl,
                        target_purl=target_norm,
                        modality="UNKNOWN",
                        status="AMBIGUOUS_MATCH",
                        evidence_source=self.provider.source_name,
                        provenance_detail=f"Ambiguous match across {len(matching_nodes)} candidates for {target_base} with specifier '{req.specifier or ''}'",
                        marker=req.marker,
                        valid_environments=active_envs,
                        candidate_refs=[m[1] for m in matching_nodes]
                    ))

                else:
                    # |C| == 0: Missing component hypothesis!
                    resolved_target_purl = target_norm
                    if resolved_target_purl not in purl_to_ref:
                        if resolved_target_purl not in candidate_nodes:
                            candidate_nodes[resolved_target_purl] = CandidateNode(
                                purl=resolved_target_purl,
                                status="INFERRED",
                                evidence_source=self.provider.source_name,
                                provenance_detail=f"Required by {current_purl} with marker '{req.marker or ''}', constraint='{req.specifier or ''}'"
                            )
                        new_ref = resolved_target_purl
                        purl_to_ref[resolved_target_purl] = new_ref
                        ref_to_purl[new_ref] = resolved_target_purl
                        queue.append((resolved_target_purl, depth + 1))

                    if is_empty_declared:
                        edge_status = "CONTRADICTED_DECLARATION"
                        contradictions.append({
                            "source": current_purl,
                            "contradicted_target": resolved_target_purl,
                            "declared_in_sbom": "dependsOn: []",
                            "evidence": self.provider.source_name,
                            "marker": req.marker,
                            "modality": modality,
                            "valid_environments": active_envs,
                            "policy": "Preserve G_obs; emit candidate repair with provenance"
                        })
                    else:
                        edge_status = "INFERRED"

                    candidate_edges.append(CandidateEdge(
                        source_purl=current_purl,
                        target_purl=resolved_target_purl,
                        modality=modality,
                        status=edge_status,
                        evidence_source=self.provider.source_name,
                        provenance_detail=f"PEP508 condition: {req.marker or 'unconditional'}",
                        marker=req.marker,
                        valid_environments=active_envs
                    ))

        # 3. Build G_reconstructed
        reconstructed_deps: Dict[str, Set[str]] = {r: set(c) for r, c in g_obs_deps.items()}
        for edge in candidate_edges:
            if edge.status == "AMBIGUOUS_MATCH" or edge.modality == "UNKNOWN":
                continue
            src_ref = purl_to_ref.get(edge.source_purl)
            tgt_ref = purl_to_ref.get(edge.target_purl)
            if src_ref and tgt_ref:
                reconstructed_deps.setdefault(src_ref, set()).add(tgt_ref)

        g_reconstructed_sbom = deepcopy(g_obs_raw)
        # Add newly inferred components
        for c_node in candidate_nodes.values():
            prefix = "pkg:pypi/"
            name_ver = c_node.purl[len(prefix):] if c_node.purl.startswith(prefix) else c_node.purl
            name, version = name_ver.rsplit("@", 1) if "@" in name_ver else (name_ver, "")
            g_reconstructed_sbom.setdefault("components", []).append({
                "type": "library",
                "bom-ref": c_node.purl,
                "purl": c_node.purl,
                "name": name,
                "version": version,
                "properties": [
                    {"name": "reconstruction:status", "value": c_node.status},
                    {"name": "reconstruction:evidence", "value": c_node.evidence_source}
                ]
            })

        g_reconstructed_sbom["dependencies"] = [
            {"ref": r, "dependsOn": sorted(children)}
            for r, children in sorted(reconstructed_deps.items())
        ]

        return {
            "environment_mode": "single_target" if target_env else "multi_context_epistemic",
            "target_environment": target_env.__dict__ if target_env else None,
            "unresolved": unresolved,
            "modality_scope": "target_environment" if target_env else "Context-Uncertain; MUST is within declared finite environment matrix only",
            "extras_by_environment": [{p: sorted(xs) for p, xs in values.items() if xs} for values in extras_by_env],
            "G_obs": g_obs_raw,
            "G_candidate": {
                "nodes": [n.__dict__ for n in candidate_nodes.values()],
                "edges": [e.__dict__ for e in candidate_edges],
                "contradictions": contradictions
            },
            "G_reconstructed": g_reconstructed_sbom,
            "summary": {
                "observed_nodes": len(components),
                "inferred_nodes": len(candidate_nodes),
                "total_reconstructed_nodes": len(components) + len(candidate_nodes),
                "observed_edges": sum(len(c) for c in g_obs_deps.values()),
                "candidate_edges": len(candidate_edges),
                "contradictions_detected": len(contradictions)
            }
        }


# =====================================================================
# MANDATORY RESEARCH BASELINES (B0, B1, B2, B3)
# =====================================================================

def run_baseline_b0_observed_only(sbom: Dict[str, Any]) -> Dict[str, Any]:
    """Baseline B0: Observed-only (Identity baseline, zero reconstruction additions)."""
    g_obs = deepcopy(sbom)
    comp_by_ref = {
        c.get("bom-ref"): normalize_purl(c.get("purl"))
        for c in [g_obs.get("metadata", {}).get("component", {})] + g_obs.get("components", [])
        if c.get("bom-ref") and c.get("purl")
    }
    obs_edges = set()
    for d in g_obs.get("dependencies", []):
        s_purl = comp_by_ref.get(d.get("ref"))
        for t_ref in d.get("dependsOn", []):
            t_purl = comp_by_ref.get(t_ref)
            if s_purl and t_purl:
                obs_edges.add((s_purl, t_purl))

    return {
        "baseline_id": "B0",
        "baseline_name": "Observed-only",
        "G_obs": g_obs,
        "G_candidate": {"nodes": [], "edges": [], "contradictions": []},
        "G_reconstructed": deepcopy(g_obs),
        "predicted_edges": obs_edges
    }


def run_baseline_b1_context_free(sbom: Dict[str, Any], provider) -> Dict[str, Any]:
    """Baseline B1: Context-free Metadata (Adds all declared requirements, ignoring markers and extras)."""
    from collections import defaultdict
    g_obs = deepcopy(sbom)
    root_comp = g_obs.get("metadata", {}).get("component", {})
    components = [root_comp] + g_obs.get("components", [])

    purl_to_ref: Dict[str, str] = {}
    pkg_name_to_purl: Dict[str, str] = {}
    for c in components:
        ref = c.get("bom-ref")
        purl = c.get("purl")
        if ref and purl:
            norm = normalize_purl(purl)
            purl_to_ref[norm] = ref
            pkg_raw = norm[len("pkg:pypi/"):].split("@")[0] if norm.startswith("pkg:pypi/") else norm
            pkg_name_to_purl[pkg_raw.lower().replace("_", "-")] = norm

    predicted_edges: Set[Tuple[str, str]] = set()
    candidate_edges: List[Dict[str, Any]] = []

    # Preserve any already observed edges
    for d in g_obs.get("dependencies", []):
        s_norm = normalize_purl(d.get("ref"))
        for t_ref in d.get("dependsOn", []):
            t_norm = normalize_purl(t_ref)
            if s_norm in purl_to_ref and t_norm in purl_to_ref:
                predicted_edges.add((s_norm, t_norm))

    for purl in list(purl_to_ref.keys()):
        reqs = provider.get_requirements(purl) or []
        for r in reqs:
            t_base = r.target_purl[len("pkg:pypi/"):].split("@")[0].lower().replace("_", "-") if r.target_purl.startswith("pkg:pypi/") else r.target_purl
            target_purl = pkg_name_to_purl.get(t_base, r.target_purl)
            predicted_edges.add((purl, target_purl))
            candidate_edges.append({
                "source_purl": purl,
                "target_purl": target_purl,
                "modality": "MUST",
                "status": "INFERRED"
            })

    reconstructed_sbom = deepcopy(g_obs)
    deps_map = defaultdict(set)
    for src, tgt in predicted_edges:
        src_ref = purl_to_ref.get(src, src)
        tgt_ref = purl_to_ref.get(tgt, tgt)
        deps_map[src_ref].add(tgt_ref)
    reconstructed_sbom["dependencies"] = [
        {"ref": r, "dependsOn": sorted(list(children))}
        for r, children in sorted(deps_map.items())
    ]

    return {
        "baseline_id": "B1",
        "baseline_name": "Context-free Metadata",
        "G_obs": g_obs,
        "G_candidate": {"nodes": [], "edges": candidate_edges, "contradictions": []},
        "G_reconstructed": reconstructed_sbom,
        "predicted_edges": predicted_edges
    }


def run_baseline_b2_maximal_supergraph(
    sbom: Dict[str, Any],
    provider,
    plausible_environments: Optional[List[TargetEnvironment]] = None
) -> Dict[str, Any]:
    """Baseline B2: Maximal Supergraph (Upper-bound recall baseline; accepts all possible edges across any env or extra)."""
    from collections import defaultdict
    envs = plausible_environments or PLAUSIBLE_ENVIRONMENTS
    all_possible_extras = {"socks", "brotli", "secure", "redis", "mongodb", "security", "aiohttp"}
    super_envs = [
        TargetEnvironment(
            os_name=e.os_name, sys_platform=e.sys_platform, platform_machine=e.platform_machine,
            python_version=e.python_version, platform_system=e.platform_system, active_extras=all_possible_extras
        )
        for e in envs
    ]

    g_obs = deepcopy(sbom)
    root_comp = g_obs.get("metadata", {}).get("component", {})
    components = [root_comp] + g_obs.get("components", [])

    purl_to_ref: Dict[str, str] = {}
    pkg_name_to_purl: Dict[str, str] = {}
    for c in components:
        ref = c.get("bom-ref")
        purl = c.get("purl")
        if ref and purl:
            norm = normalize_purl(purl)
            purl_to_ref[norm] = ref
            pkg_raw = norm[len("pkg:pypi/"):].split("@")[0] if norm.startswith("pkg:pypi/") else norm
            pkg_name_to_purl[pkg_raw.lower().replace("_", "-")] = norm

    predicted_edges: Set[Tuple[str, str]] = set()
    candidate_edges: List[Dict[str, Any]] = []

    for purl in list(purl_to_ref.keys()):
        reqs = provider.get_requirements(purl) or []
        for r in reqs:
            t_base = r.target_purl[len("pkg:pypi/"):].split("@")[0].lower().replace("_", "-") if r.target_purl.startswith("pkg:pypi/") else r.target_purl
            target_purl = pkg_name_to_purl.get(t_base, r.target_purl)
            is_possible = False
            for se in super_envs:
                for extra_candidate in [None] + list(all_possible_extras):
                    if evaluate_pep508_marker(r.marker or "", se, extra=extra_candidate):
                        is_possible = True
                        break
                if is_possible:
                    break

            if is_possible:
                predicted_edges.add((purl, target_purl))
                candidate_edges.append({
                    "source_purl": purl,
                    "target_purl": target_purl,
                    "modality": "MAY_ONLY",
                    "status": "INFERRED"
                })

    reconstructed_sbom = deepcopy(g_obs)
    deps_map = defaultdict(set)
    for src, tgt in predicted_edges:
        src_ref = purl_to_ref.get(src, src)
        tgt_ref = purl_to_ref.get(tgt, tgt)
        deps_map[src_ref].add(tgt_ref)
    reconstructed_sbom["dependencies"] = [
        {"ref": r, "dependsOn": sorted(list(children))}
        for r, children in sorted(deps_map.items())
    ]

    return {
        "baseline_id": "B2",
        "baseline_name": "Maximal Supergraph",
        "G_obs": g_obs,
        "G_candidate": {"nodes": [], "edges": candidate_edges, "contradictions": []},
        "G_reconstructed": reconstructed_sbom,
        "predicted_edges": predicted_edges
    }


def run_baseline_b3_context_aware(
    sbom: Dict[str, Any],
    provider,
    target_env: Optional[TargetEnvironment] = None,
    candidate_environments: Optional[List[TargetEnvironment]] = None
) -> Dict[str, Any]:
    """Baseline B3: Context-Aware Deterministic Heuristic."""
    resolver = ContextAwareResolver(provider)
    res = resolver.resolve(sbom, target_env=target_env, candidate_environments=candidate_environments)
    reconstructed_cdx = res["G_reconstructed"]
    comp_by_ref = {
        c.get("bom-ref"): normalize_purl(c.get("purl"))
        for c in [reconstructed_cdx.get("metadata", {}).get("component", {})] + reconstructed_cdx.get("components", [])
        if c.get("bom-ref") and c.get("purl")
    }
    pred_edges = set()
    for d in reconstructed_cdx.get("dependencies", []):
        s_purl = comp_by_ref.get(d.get("ref"))
        for t_ref in d.get("dependsOn", []):
            t_purl = comp_by_ref.get(t_ref)
            if s_purl and t_purl:
                pred_edges.add((s_purl, t_purl))
    res["baseline_id"] = "B3"
    res["baseline_name"] = "Context-aware Deterministic Heuristic"
    res["predicted_edges"] = pred_edges
    return res

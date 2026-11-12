#!/usr/bin/env python3
"""Repository selection for EAGER-SBOM pilot benchmark.

Identifies 20 repositories (10 npm + 10 Cargo) meeting inclusion criteria:
- Active maintenance (commits within 6 months)
- Dependency complexity (15-100 dependencies)
- Lockfile present
- Multi-tool SBOM discrepancies
- Known vulnerabilities in dependency tree
"""
import json
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional


@dataclass
class RepositoryCandidate:
    """Repository metadata for pilot selection."""
    repo_url: str
    ecosystem: str  # "npm" or "cargo"
    star_count: int
    last_commit_days_ago: int
    has_lockfile: bool
    dependency_count: int
    conflict_potential: float  # 0-1 score
    known_cves: int
    selection_reason: str
    excluded: bool = False
    exclusion_reason: Optional[str] = None


# Curated candidate repositories for pilot
NPM_CANDIDATES = [
    "https://github.com/expressjs/express",
    "https://github.com/lodash/lodash",
    "https://github.com/axios/axios",
    "https://github.com/vercel/next.js",
    "https://github.com/sindresorhus/got",
    "https://github.com/fastify/fastify",
    "https://github.com/request/request",
    "https://github.com/chalk/chalk",
    "https://github.com/debug-js/debug",
    "https://github.com/cheeriojs/cheerio",
    "https://github.com/moment/moment",
    "https://github.com/socketio/socket.io",
    "https://github.com/yargs/yargs",
    "https://github.com/jprichardson/node-fs-extra",
    "https://github.com/shelljs/shelljs",
]

CARGO_CANDIDATES = [
    "https://github.com/tokio-rs/tokio",
    "https://github.com/serde-rs/serde",
    "https://github.com/rust-lang/regex",
    "https://github.com/actix/actix-web",
    "https://github.com/clap-rs/clap",
    "https://github.com/hyperium/hyper",
    "https://github.com/rayon-rs/rayon",
    "https://github.com/rust-lang/log",
    "https://github.com/BurntSushi/ripgrep",
    "https://github.com/sharkdp/fd",
    "https://github.com/ogham/exa",
    "https://github.com/meilisearch/meilisearch",
    "https://github.com/alacritty/alacritty",
    "https://github.com/xi-editor/xi-editor",
    "https://github.com/rustwasm/wasm-pack",
]


def check_repository_eligibility(repo_url: str, ecosystem: str) -> RepositoryCandidate:
    """Check if repository meets pilot inclusion criteria."""
    # This is a template - actual implementation would:
    # 1. Clone repo to temp directory
    # 2. Check for lockfile
    # 3. Parse dependencies
    # 4. Run multiple SBOM generators
    # 5. Detect conflicts
    # 6. Query OSV for CVEs

    # Placeholder implementation
    return RepositoryCandidate(
        repo_url=repo_url,
        ecosystem=ecosystem,
        star_count=0,  # Would fetch from GitHub API
        last_commit_days_ago=30,  # Would check git log
        has_lockfile=True,  # Would check filesystem
        dependency_count=50,  # Would parse lockfile
        conflict_potential=0.7,  # Would compare SBOM outputs
        known_cves=2,  # Would query OSV
        selection_reason="Manual review pending",
        excluded=False
    )


def score_repository(candidate: RepositoryCandidate) -> float:
    """Score repository suitability for pilot (higher is better)."""
    if candidate.excluded:
        return 0.0

    score = 0.0

    # Recency (0-20 points)
    if candidate.last_commit_days_ago <= 180:
        score += 20 * (1 - candidate.last_commit_days_ago / 180)

    # Dependency complexity (0-25 points)
    if 15 <= candidate.dependency_count <= 100:
        score += 25
    elif candidate.dependency_count > 100:
        score += 15

    # Conflict potential (0-30 points)
    score += 30 * candidate.conflict_potential

    # Known CVEs (0-15 points)
    score += min(15, candidate.known_cves * 5)

    # Lockfile present (0-10 points)
    if candidate.has_lockfile:
        score += 10

    return score


def select_pilot_repositories(
    npm_candidates: List[str],
    cargo_candidates: List[str],
    target_npm: int = 10,
    target_cargo: int = 10
) -> dict:
    """Select balanced set of repositories for pilot."""

    print("Evaluating npm candidates...")
    npm_evaluated = []
    for url in npm_candidates[:target_npm * 2]:  # Evaluate 2x target
        candidate = check_repository_eligibility(url, "npm")
        score = score_repository(candidate)
        npm_evaluated.append((score, candidate))

    print("Evaluating Cargo candidates...")
    cargo_evaluated = []
    for url in cargo_candidates[:target_cargo * 2]:
        candidate = check_repository_eligibility(url, "cargo")
        score = score_repository(candidate)
        cargo_evaluated.append((score, candidate))

    # Select top N by score
    npm_selected = sorted(npm_evaluated, reverse=True, key=lambda x: x[0])[:target_npm]
    cargo_selected = sorted(cargo_evaluated, reverse=True, key=lambda x: x[0])[:target_cargo]

    return {
        "selection_date": datetime.now().isoformat(),
        "npm_repositories": [
            {**asdict(c), "selection_score": s}
            for s, c in npm_selected
        ],
        "cargo_repositories": [
            {**asdict(c), "selection_score": s}
            for s, c in cargo_selected
        ],
        "selection_criteria": {
            "last_commit_max_days": 180,
            "dependency_count_min": 15,
            "dependency_count_max": 100,
            "lockfile_required": True,
            "min_conflict_potential": 0.3,
            "min_known_cves": 1
        }
    }


def main():
    """Generate pilot repository selection manifest."""
    output_dir = Path(__file__).parent
    output_file = output_dir / "repository_manifest.json"

    print("EAGER-SBOM Pilot Repository Selection")
    print("=" * 50)

    selection = select_pilot_repositories(NPM_CANDIDATES, CARGO_CANDIDATES)

    print(f"\nSelected {len(selection['npm_repositories'])} npm repositories")
    print(f"Selected {len(selection['cargo_repositories'])} Cargo repositories")

    output_file.write_text(json.dumps(selection, indent=2))
    print(f"\nManifest written to: {output_file}")

    print("\nNext steps:")
    print("1. Manual review of selected repositories")
    print("2. Evidence collection for each repository")
    print("3. Oracle construction with conflict adjudication")
    print("4. Baseline and LLM evaluation runs")


if __name__ == "__main__":
    main()

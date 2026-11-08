#!/usr/bin/env python3
"""Browser acceptance checks and a real screenshot of the generated local Workbench."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from research_core import digest, save


def verify(folder):
    from playwright.sync_api import sync_playwright
    folder = Path(folder).resolve()
    errors = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1050})
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto((folder / "index.html").as_uri())
        assert page.title() == "SBOM Research Workbench"
        page.get_by_role("button", name="Dependency Graph", exact=True).click()
        counts = page.evaluate("({original:edges(state().d.observed).length,after:edges(state().s.output).length})")
        assert page.locator(".edge").count() == counts["after"]
        page.get_by_role("button", name="Original distribution view", exact=True).click()
        assert page.locator(".edge").count() == counts["original"]
        page.get_by_role("button", name="Reconstructed candidates", exact=True).click()
        page.locator(".edge").first.press("Enter")
        assert "OBSERVED DECLARATION" in page.locator(".inspector").inner_text()
        view_count = 0
        for view in ("Evidence & Scope", "Experiments", "Paper Reproduction", "Security", "Agent", "Overview"):
            page.get_by_role("button", name=view, exact=True).click()
            assert page.locator("#content").inner_text().strip()
            view_count += 1
        # Selecting tracks must change the data-kind label, not reuse displayed metrics.
        page.locator("#runSelect").select_option("3")
        assert "CONTROLLED MASKING" in page.locator("#kind").inner_text()
        for regime in ("partial", "wheel", "sdist"):
            page.locator("#regime").select_option(regime)
            expected = page.evaluate("state().s.scores.B3.reference_edges")
            assert page.locator(".card .value").first.inner_text() == str(expected)
        # Missing optional metrics render as undefined rather than fabricated success.
        page.evaluate("state().s.scores.B3.whole_graph.precision=null;render()")
        assert page.locator('.split .panel').first.locator('tbody tr').nth(3).locator('td').nth(4).inner_text() == '—'
        page.evaluate("state().d.project='<img src=x onerror=window.injected=true>';render()")
        assert page.locator("#content img").count() == 0
        assert page.evaluate("window.injected===undefined")
        page.reload()
        all_links = page.evaluate("DATA.datasets.flatMap(d=>[...Object.values(d.links),...Object.values(d.snapshots).flatMap(s=>Object.values(s.links))]).concat(Object.values(DATA.paper_links))")
        for relative in all_links:
            assert (folder / relative).resolve().is_file(), relative
        page.screenshot(path=str(folder / "screenshot.png"), full_page=True)
        page.get_by_role("button", name="Dependency Graph", exact=True).click()
        page.screenshot(path=str(folder / "graph_screenshot.png"), full_page=True)
        assert not errors, errors
        save(folder / "browser_validation.json", {"status": "PASS", "tested_at": datetime.now(timezone.utc).isoformat(),
            "browser": browser.version, "index_sha256": digest(folder / "index.html"), "javascript_errors": errors,
            "checks": ["All seven screens render", "Original/reconstructed edge counts match source JSON",
                       "Keyboard edge selection updates inspector", "Project/evidence selection updates metrics",
                       "Undefined metrics stay undefined", "Untrusted project text is inert", "Artifact links resolve"],
            "artifact_links_checked": len(all_links), "screenshots": ["screenshot.png", "graph_screenshot.png"]})
        browser.close()
    print("Workbench browser acceptance: PASS")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, default=ROOT / "results/research_workbench")
    verify(p.parse_args().out)

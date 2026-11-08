/* Optional browser integration check: Playwright and a local UI server required. */
const fs = require('node:fs/promises');
const path = require('node:path');
const { chromium } = require('playwright');

(async () => {
  const out = path.resolve(process.argv[2]);
  await fs.mkdir(out, { recursive: false });
  const browser = await chromium.launch({
    headless: true,
    ...(process.env.SBOM_CHROMIUM ? { executablePath: process.env.SBOM_CHROMIUM } : {}),
    args: ['--no-sandbox'],
  });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  try {
    await page.goto(process.env.SBOM_UI_URL || 'http://127.0.0.1:8088');
    await page.locator('#project option').first().waitFor({ state: 'attached' });
    if (await page.locator('#budget').inputValue() !== 'unlimited') throw new Error('Default must be unrestricted');
    await page.locator('#history .item').filter({ hasText: 'AI Agent' }).first().click();
    await page.locator('#result').waitFor({ state: 'visible' });
    const agentRun = await page.locator('#run-id').textContent();
    await page.locator('#before-graph .node').first().click();
    const selected = Boolean(await page.locator('#node-detail').textContent());
    await page.locator('#graph-scope').selectOption('all');
    await page.locator('#graph-scope').selectOption('candidates');
    await page.screenshot({ path: path.join(out, 'desktop.png'), fullPage: true });
    await page.locator('[data-tab="changes"]').click();
    await page.locator('#source-list button').first().click();
    await page.waitForFunction(() => document.getElementById('source-content').textContent.startsWith('SHA-256:'));
    await page.locator('[data-tab="risk"]').click();
    await page.locator('#risk-note').waitFor({ state: 'visible' });
    await page.screenshot({ path: path.join(out, 'risk.png'), fullPage: true });
    // Exactly one deterministic submission, never a paid LLM episode.
    await page.locator('#policy').selectOption('fixed_order');
    await page.locator('#budget').selectOption('4');
    const responsePromise = page.waitForResponse(r => r.url().endsWith('/api/agent/run') && r.request().method() === 'POST');
    await page.locator('#run').click();
    const submitted = await (await responsePromise).json();
    await page.waitForFunction(run => document.getElementById('run-id').textContent === run,
                               submitted.run_id, { timeout: 180000 });
    await page.locator('[data-tab="graph"]').click();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: path.join(out, 'mobile.png'), fullPage: true });
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth);
    const result = { browser: browser.version(), live_agent_history_loaded: agentRun,
      evidence_preview_loaded: true, risk_panel_loaded: true, node_selected: selected,
      graph_scope_toggle: true, control_job_completed: submitted.run_id,
      mobile_horizontal_overflow: overflow, page_errors: errors };
    await fs.writeFile(path.join(out, 'verification.json'), JSON.stringify(result, null, 2) + '\n');
    if (overflow || errors.length) throw new Error('Browser checks failed');
    process.stdout.write(JSON.stringify(result) + '\n');
  } finally {
    await browser.close();
  }
})().catch(error => { process.stderr.write(error.stack + '\n'); process.exitCode = 1; });

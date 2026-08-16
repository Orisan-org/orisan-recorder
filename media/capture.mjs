/**
 * Capture the five interface screenshots used in media/.
 *
 *   node media/capture.mjs <greenLogDir> <tamperedLogDir> <tsaCa> <payloadKey?>
 *
 * Both directories must be REAL logs in the state they claim: the first
 * verifying CLEAN against the hosted witness, the second left TAMPERED by
 * `orisan-rec showcase`. Nothing here fabricates a banner state — the pages
 * are whatever the running server reports for those logs.
 */
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import puppeteer from 'puppeteer';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '..');
const [greenDir, tamperedDir, tsaCa, payloadKey, scanHome] = process.argv.slice(2);
if (!greenDir || !tamperedDir || !tsaCa) {
  console.error('usage: capture.mjs <greenLogDir> <tamperedLogDir> <tsaCa> [payloadKey] [scanHome]');
  process.exit(2);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function serve(dir, port, ca) {
  const args = [join(repo, 'dist', 'cli.js'), 'ui', dir, '--port', String(port), '--tsa-ca', ca];
  // A screenshot of a real Agents screen is an inventory of the machine that
  // took it: username, installed clients, project names, process ids. The
  // published images scan a fabricated root instead.
  if (scanHome) args.push('--scan-home', scanHome);
  if (payloadKey) args.push('--payload-key', payloadKey);
  const child = spawn(process.execPath, args, { stdio: 'ignore' });
  return child;
}

async function waitFor(page, url, tries = 40) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await page.goto(url, { waitUntil: 'networkidle2', timeout: 4000 });
      if (r && r.ok()) return true;
    } catch { /* server still starting */ }
    await sleep(500);
  }
  return false;
}

const nav = async (page, name) => {
  await page.evaluate((n) => {
    const b = [...document.querySelectorAll('.nav button')]
      .find((x) => x.textContent.trim().toLowerCase().startsWith(n));
    if (b) b.click();
  }, name);
  await sleep(900);
};

const dismissTour = async (page) => {
  await page.evaluate(() => {
    const skip = [...document.querySelectorAll('.tour-actions button')].find((b) => b.textContent === 'Skip');
    if (skip) skip.click();
  });
  await sleep(400);
};

const shot = async (page, file, height) => {
  await page.setViewport({ width: 1280, height });
  await sleep(300);
  await page.screenshot({ path: join(here, file) });
  console.log('  wrote', file);
};

const browser = await puppeteer.launch({ headless: 'new' });
const page = await browser.newPage();

// ---- green log ------------------------------------------------------------
const greenSrv = serve(greenDir, 4321, tsaCa);
try {
  if (!(await waitFor(page, 'http://127.0.0.1:4321/'))) throw new Error('green server never came up');
  await dismissTour(page);

  // 1. discovery — the wedge
  await nav(page, 'agents');
  await shot(page, '1-agents.png', 760);

  // 2. green banner, expanded to show what was and was not checked
  await nav(page, 'timeline');
  await page.evaluate(() => document.querySelector('.banner')?.click());
  await sleep(500);
  const tone = await page.evaluate(() => document.querySelector('.banner')?.className ?? '');
  if (!tone.includes('banner-green')) throw new Error(`expected a green banner, got "${tone}"`);
  await shot(page, '2-verified.png', 820);

  // 3. one action, opened up
  await page.evaluate(() => {
    document.querySelector('.banner')?.click();
    const rows = [...document.querySelectorAll('tbody tr.clickable')];
    (rows.find((r) => r.textContent.includes('model_call')) ?? rows[0])?.click();
  });
  await sleep(900);
  await page.evaluate(() => document.querySelector('tr.expand')?.scrollIntoView({ block: 'center' }));
  await sleep(300);
  await shot(page, '3-event-detail.png', 820);

  // 5. why trust this — run the real tamper demo on this log
  await nav(page, 'why');
  await page.evaluate(() => {
    const b = [...document.querySelectorAll('button')].find((x) => x.textContent.includes('Prove it on my log'));
    if (b) b.click();
  });
  await sleep(6000);
  await page.evaluate(() => document.querySelector('.prove-run')?.scrollIntoView({ block: 'start' }));
  await sleep(400);
  await shot(page, '5-prove-it.png', 900);
} finally {
  greenSrv.kill('SIGKILL');
}

// ---- tampered log ---------------------------------------------------------
const redSrv = serve(tamperedDir, 4322, join(tamperedDir, 'tsa-ca.pem'));
try {
  if (!(await waitFor(page, 'http://127.0.0.1:4322/'))) throw new Error('tampered server never came up');
  await dismissTour(page);
  await nav(page, 'timeline');
  await page.evaluate(() => document.querySelector('.banner')?.click());
  await sleep(500);
  const tone = await page.evaluate(() => document.querySelector('.banner')?.className ?? '');
  if (!tone.includes('banner-red')) throw new Error(`expected a red banner, got "${tone}"`);
  await shot(page, '4-tampered.png', 760);
} finally {
  redSrv.kill('SIGKILL');
}

await browser.close();
console.log('\n  all five captured from real logs, banner states asserted');

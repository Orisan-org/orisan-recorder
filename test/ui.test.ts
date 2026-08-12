/**
 * R2.3/R2.4 — the server, the evidence bundle, and the built UI bundle.
 *
 * The bundle grep is the important one: banner.ts can be perfectly correct and
 * a React component can still hard-code "integrity verified" in a heading. The
 * only way to catch that is to read the shipped artefact.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { FALSE_CONFIDENCE_STRINGS } from '../src/banner.js';
import { buildEvidenceBundle, VERIFY_INSTRUCTIONS } from '../src/bundle.js';
import { makeZip } from '../src/zip.js';
import { hostIsLoopback, startServer } from '../src/server.js';
import { Recorder } from '../src/recorder.js';
import { verify } from '../src/verify.js';

const UI_DIST = join(process.cwd(), 'ui', 'dist');

describe('the built UI bundle makes no false claims', () => {
  const bundleText = (): string => {
    const assets = join(UI_DIST, 'assets');
    let text = readFileSync(join(UI_DIST, 'index.html'), 'utf8');
    for (const f of readdirSync(assets)) text += readFileSync(join(assets, f), 'utf8');
    return text.toLowerCase();
  };

  it('the bundle exists (run `npm run build:ui` first)', () => {
    expect(existsSync(join(UI_DIST, 'index.html'))).toBe(true);
  });

  it('contains no hard-coded false-confidence string', () => {
    const text = bundleText();
    const hits = FALSE_CONFIDENCE_STRINGS.filter((s) => text.includes(s));
    expect(hits).toEqual([]);
  });

  it('contains no reassuring word at all outside data from the server', () => {
    // The UI must not author reassurance. Every such string comes from
    // bannerFor(), which is tested separately.
    const text = bundleText();
    for (const banned of ['tamper-proof', 'guaranteed', 'provably secure', 'immutable log']) {
      expect(text, `bundle contains "${banned}"`).not.toContain(banned);
    }
  });

  it('does ship the honest grey headline', () => {
    // Not strictly required (the server supplies it), but if the UI ever
    // inlines a headline it must be this one.
    expect(bundleText()).not.toContain('integrity verified');
  });
});

describe('zip writer', () => {
  it('produces an archive the system unzip accepts', () => {
    const dir = mkdtempSync(join(tmpdir(), 'orisan-zip-'));
    try {
      const zip = makeZip([
        { path: 'a.txt', data: Buffer.from('hello') },
        { path: 'nested/b.json', data: Buffer.from(JSON.stringify({ a: 1 }).repeat(50)) },
      ]);
      const zipPath = join(dir, 'out.zip');
      writeFileSync(zipPath, zip);
      const listing = execFileSync('unzip', ['-l', zipPath], { encoding: 'utf8' });
      expect(listing).toMatch(/a\.txt/);
      expect(listing).toMatch(/nested\/b\.json/);
      execFileSync('unzip', ['-q', '-o', zipPath, '-d', join(dir, 'x')]);
      expect(readFileSync(join(dir, 'x', 'a.txt'), 'utf8')).toBe('hello');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('evidence bundle', () => {
  let dir: string; let keyDir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'orisan-bundle-'));
    keyDir = mkdtempSync(join(tmpdir(), 'orisan-bundlekey-'));
  });
  afterEach(() => { for (const d of [dir, keyDir]) rmSync(d, { recursive: true, force: true }); });

  async function seed(): Promise<void> {
    const rec = Recorder.open(dir, {
      checkpointInterval: 5, fsync: false, anchor: { enabled: false },
      signingKeyPath: join(keyDir, 'signing.key'),
    });
    for (let i = 0; i < 10; i++) {
      await rec.record({
        actor: { human: 'a', agent_id: 'spiffe://x', tool: 't' },
        kind: 'tool_call', target: `t${i}`, args_digest: null,
        payload_ref: null, outcome: 'ok', duration_ms: 1,
      });
    }
    await rec.end();
  }

  it('ACCEPTANCE: contains everything a third party needs, and nothing secret', async () => {
    await seed();
    const zip = buildEvidenceBundle(dir, { report: verify(dir) });
    const out = mkdtempSync(join(tmpdir(), 'orisan-unzip-'));
    try {
      const zp = join(out, 'b.zip');
      writeFileSync(zp, zip);
      execFileSync('unzip', ['-q', '-o', zp, '-d', join(out, 'x')]);
      const files = readdirSync(join(out, 'x'));

      expect(files).toContain('events-0000.jsonl');
      expect(files).toContain('checkpoints.jsonl');
      expect(files).toContain('signing.pub.pem');
      expect(files).toContain('VERIFY.md');
      expect(files).toContain('verify-report.json');

      // The private key must never travel.
      expect(files).not.toContain('signing.key');
      const all = files.map((f) => readFileSync(join(out, 'x', f), 'utf8')).join('');
      expect(all).not.toContain('"private_key"');
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  });

  it('the instructions tell the reader what the bundle cannot prove', () => {
    expect(VERIFY_INSTRUCTIONS).toMatch(/cannot tell you/i);
    expect(VERIFY_INSTRUCTIONS).toMatch(/witness/i);
    expect(VERIFY_INSTRUCTIONS).toMatch(/not a pass/);
  });

  it('the instructions never claim the bundle is verified', () => {
    const lower = VERIFY_INSTRUCTIONS.toLowerCase();
    for (const s of FALSE_CONFIDENCE_STRINGS) expect(lower).not.toContain(s);
  });
});

describe('the server', () => {
  let dir: string; let keyDir: string; let stop: (() => Promise<void>) | null = null; let base = '';

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'orisan-srv-'));
    keyDir = mkdtempSync(join(tmpdir(), 'orisan-srvkey-'));
    const rec = Recorder.open(dir, {
      checkpointInterval: 5, fsync: false, anchor: { enabled: false },
      signingKeyPath: join(keyDir, 'signing.key'),
    });
    for (let i = 0; i < 8; i++) {
      await rec.record({
        actor: { human: 'a', agent_id: 'spiffe://x', tool: 't' },
        kind: i === 3 ? 'flag' : 'tool_call', target: `t${i}`, args_digest: null,
        payload_ref: null, outcome: 'ok', duration_ms: 2,
      });
    }
    await rec.end();
    const s = await startServer({ logDir: dir, port: 0, shimPath: join(process.cwd(), 'src', 'shim-main.ts'), uiDir: UI_DIST });
    stop = s.close;
    base = `http://127.0.0.1:${(s as unknown as { port: number }).port}`;
  }, 30_000);

  afterAll(async () => {
    if (stop) await stop();
    for (const d of [dir, keyDir]) rmSync(d, { recursive: true, force: true });
  });

  it('rejects a non-loopback Host header', () => {
    expect(hostIsLoopback('localhost:4173')).toBe(true);
    expect(hostIsLoopback('127.0.0.1:4173')).toBe(true);
    expect(hostIsLoopback('evil.example.com')).toBe(false);
    expect(hostIsLoopback(undefined)).toBe(false);
  });

  it('ACCEPTANCE: status shows grey "cannot prove completeness", not green', async () => {
    const r = await fetch(`${base}/api/status`);
    const body = (await r.json()) as { exitCode: number; banner: { tone: string; headline: string; detail: string } };
    expect(body.exitCode).toBe(2);
    expect(body.banner.tone).toBe('grey');
    expect(body.banner.headline).toBe('Cannot prove completeness');
    expect(`${body.banner.headline} ${body.banner.detail}`.toLowerCase()).not.toMatch(/verif/);
  });

  it('serves events with the flagged one present', async () => {
    const r = await fetch(`${base}/api/events`);
    const body = (await r.json()) as { events: { kind: string }[] };
    expect(body.events).toHaveLength(8);
    expect(body.events.filter((e) => e.kind === 'flag')).toHaveLength(1);
  });

  it('serves a scan', async () => {
    const r = await fetch(`${base}/api/scan`);
    const body = (await r.json()) as { surfaces: unknown[] };
    expect(Array.isArray(body.surfaces)).toBe(true);
  });

  it('exports a zip', async () => {
    const r = await fetch(`${base}/api/export`);
    expect(r.headers.get('content-type')).toBe('application/zip');
    const buf = Buffer.from(await r.arrayBuffer());
    expect(buf.subarray(0, 4).toString('hex')).toBe('504b0304');
  });

  it('serves the UI', async () => {
    const r = await fetch(`${base}/`);
    expect(r.status).toBe(200);
    expect(await r.text()).toMatch(/<div id="root">/);
  });
});

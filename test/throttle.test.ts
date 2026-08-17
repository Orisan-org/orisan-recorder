/**
 * Issue #11 — a 429 is a request to slow down, not a refusal.
 *
 * The client checked only `res.ok` and turned every non-2xx into
 * `witness refused (<status>)`. To an operator that reads as the witness
 * objecting to what was sent, when in fact the witness is rate-limiting and
 * the submission is fine.
 *
 * Nothing was ever lost — unwitnessed checkpoints are re-derived from disk as
 * an offline queue — but the recorder had no backoff, so a throttled client
 * kept walking into the wall and reporting failures.
 *
 * Both halves are tested: the unit behaviour against a scripted fetch, and the
 * whole thing against a REAL HTTP witness that answers 429 and then succeeds.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawn } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';

import { Recorder } from '../src/recorder.js';
import { readCheckpoints, generateSigningKey, type SigningKeyFile } from '../src/checkpoint.js';
import {
  DEFAULT_RETRY, DRAIN_RETRY, RETRYABLE_STATUS, pendingSubmissions, receiptPath, registerLog,
  retryDelayMs, submitCheckpoint, readWitnessConfig,
  type FetchLike, type WitnessConfig,
} from '../src/witness-service.js';
import { startWitness, type LiveWitness } from './fixtures/witness-fixture.js';

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'orisan-429-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

describe('retryDelayMs', () => {
  it('honours a Retry-After given in seconds', () => {
    expect(retryDelayMs(0, '2')).toBe(2000);
    expect(retryDelayMs(3, '1')).toBe(1000);
  });

  it('honours a Retry-After given as an HTTP-date', () => {
    const when = new Date(Date.now() + 3000).toUTCString();
    expect(retryDelayMs(0, when)).toBeGreaterThan(1500);
    expect(retryDelayMs(0, when)).toBeLessThanOrEqual(8000);
  });

  it('caps a hostile Retry-After rather than sleeping for a day', () => {
    expect(retryDelayMs(0, '86400')).toBe(8000);
  });

  it('never returns a negative delay for a Retry-After in the past', () => {
    expect(retryDelayMs(0, new Date(Date.now() - 60_000).toUTCString())).toBe(0);
  });

  it('falls back to exponential backoff when there is no header', () => {
    // Jitter pinned so the growth is assertable.
    expect(retryDelayMs(0, null, 1)).toBe(400);
    expect(retryDelayMs(1, null, 1)).toBe(800);
    expect(retryDelayMs(2, null, 1)).toBe(1600);
    expect(retryDelayMs(9, null, 1)).toBe(8000);
  });

  it('jitters, so throttled recorders do not retry in lockstep', () => {
    expect(retryDelayMs(2, null, 0)).toBe(800);
    expect(retryDelayMs(2, null, 1)).toBe(1600);
  });

  it('ignores an unparseable Retry-After instead of hammering', () => {
    expect(retryDelayMs(0, 'soon-ish', 1)).toBe(400);
  });
});

describe('a throttled submission, against a scripted witness', () => {
  const cfg: WitnessConfig = {
    url: 'https://witness.example', log_id: '00000000-0000-4000-8000-000000000001',
    witness_pubkey_pem: 'unused because we never get a receipt',
  } as WitnessConfig;

  const cp = { index: 0, seq_from: 0, seq_to: 9, merkle_root: 'a'.repeat(64) } as never;
  // A real key: the submission is signed before the request goes out, so a
  // stub would fail in the signer and never exercise the 429 path at all.
  let key: SigningKeyFile;
  beforeEach(() => { key = generateSigningKey(dir); });

  /** Answers `status` for `times` requests, then a hard 500. */
  function scripted(times: number, retryAfter?: string, status = 429): { f: FetchLike; calls: () => number } {
    let n = 0;
    const f: FetchLike = async () => {
      n++;
      if (n <= times) {
        return {
          ok: false, status,
          text: async () => 'busy',
          json: async () => ({}),
          headers: { get: (h: string) => (h.toLowerCase() === 'retry-after' ? retryAfter ?? null : null) },
        };
      }
      return { ok: false, status: 500, text: async () => 'boom', json: async () => ({}) };
    };
    return { f, calls: () => n };
  }

  it('retries rather than reporting a refusal on the first 429', async () => {
    const { f, calls } = scripted(1);
    const r = await submitCheckpoint(dir, cfg, key, cp, f, { sleep: async () => {} });
    expect(calls()).toBe(2);
    // Second call returned 500, so this is a genuine refusal — and it says so.
    expect(r.error).toContain('witness refused (500)');
    expect(r.transient).toBeUndefined();
  });

  it('gives up within the budget and calls it throttled, never refused', async () => {
    const { f, calls } = scripted(99);
    const r = await submitCheckpoint(dir, cfg, key, cp, f, { sleep: async () => {} });
    expect(calls()).toBe(DEFAULT_RETRY.maxAttempts);
    expect(r.ok).toBe(false);
    expect(r.transient).toBe(true);
    expect(r.status).toBe(429);
    expect(r.error).toContain('throttled');
    expect(r.error).not.toContain('refused');
    expect(r.error).toContain('stays queued');
  });

  it('waits as long as Retry-After asks, not its own backoff', async () => {
    const slept: number[] = [];
    const { f } = scripted(99, '2');
    await submitCheckpoint(dir, cfg, key, cp, f, {
      sleep: async (ms) => { slept.push(ms); }, maxAttempts: 3, maxTotalMs: 60_000,
    });
    expect(slept).toEqual([2000, 2000]);
  });

  it('stops early rather than exceeding its total time budget', async () => {
    const slept: number[] = [];
    const { f, calls } = scripted(99, '5');
    const r = await submitCheckpoint(dir, cfg, key, cp, f, {
      sleep: async (ms) => { slept.push(ms); }, maxAttempts: 10, maxTotalMs: 6_000,
    });
    // 5s fits once; a second 5s would blow the 6s budget.
    expect(slept).toEqual([5000]);
    expect(calls()).toBe(2);
    expect(r.transient).toBe(true);
  });

  it('the recorder budget is small, so recording is never blocked for long', () => {
    expect(DEFAULT_RETRY.maxTotalMs).toBeLessThanOrEqual(5_000);
    expect(DRAIN_RETRY.maxTotalMs).toBeGreaterThan(DEFAULT_RETRY.maxTotalMs);
  });

  it('retries every status in the retry class, and no others', async () => {
    for (const status of [429, 502, 503, 504]) {
      const { f, calls } = scripted(99, undefined, status);
      const r = await submitCheckpoint(dir, cfg, key, cp, f, { sleep: async () => {} });
      expect(calls(), `status ${status} should be retried`).toBe(DEFAULT_RETRY.maxAttempts);
      expect(r.transient, `status ${status}`).toBe(true);
      expect(r.status).toBe(status);
    }
    // 500 is not in the class: a witness that genuinely broke on this content
    // will break the same way on the retry.
    for (const status of [400, 401, 404, 409, 500, 501]) {
      const { f, calls } = scripted(99, undefined, status);
      const r = await submitCheckpoint(dir, cfg, key, cp, f, { sleep: async () => {} });
      expect(calls(), `status ${status} should NOT be retried`).toBe(1);
      expect(r.transient, `status ${status}`).toBeUndefined();
    }
    expect([...RETRYABLE_STATUS].sort()).toEqual([429, 502, 503, 504]);
  });

  it('says unavailable for a 5xx and throttled for a 429, not one word for both', async () => {
    const throttled = await submitCheckpoint(dir, cfg, key, cp, scripted(99, '1', 429).f, { sleep: async () => {} });
    expect(throttled.error).toContain('throttled');
    expect(throttled.error).toContain('asking for 1s');

    const down = await submitCheckpoint(dir, cfg, key, cp, scripted(99, undefined, 503).f, { sleep: async () => {} });
    expect(down.error).toContain('temporarily unavailable (503)');
    expect(down.error).not.toContain('throttled');
    for (const r of [throttled, down]) {
      expect(r.error).not.toContain('refused');
      expect(r.error).toContain('stays queued');
    }
  });

  it('honours Retry-After on a 503 as well as a 429', async () => {
    const slept: number[] = [];
    await submitCheckpoint(dir, cfg, key, cp, scripted(99, '2', 503).f, {
      sleep: async (ms) => { slept.push(ms); }, maxAttempts: 3, maxTotalMs: 60_000,
    });
    expect(slept).toEqual([2000, 2000]);
  });

  it('does not retry a 409 fork, which is a real refusal', async () => {
    let n = 0;
    const f: FetchLike = async () => {
      n++;
      return { ok: false, status: 409, text: async () => 'fork', json: async () => ({}) };
    };
    const r = await submitCheckpoint(dir, cfg, key, cp, f, { sleep: async () => {} });
    expect(n).toBe(1);
    expect(r.conflict).toBe(true);
    expect(r.transient).toBeUndefined();
  });

  it('does not retry an unreachable witness into a long stall', async () => {
    let n = 0;
    const f: FetchLike = async () => { n++; throw new Error('ECONNREFUSED'); };
    const r = await submitCheckpoint(dir, cfg, key, cp, f, { sleep: async () => {} });
    expect(n).toBe(1);
    expect(r.error).toContain('unreachable');
  });
});

describe('a retryable status then success, against a real witness over HTTP', () => {
  let witness: LiveWitness;
  let proxy: Server;
  let proxyUrl: string;
  let deferNext = 0;
  let deferStatus = 429;
  let seenDeferrals = 0;

  beforeEach(async () => {
    witness = await startWitness();
    deferNext = 0;
    deferStatus = 429;
    seenDeferrals = 0;
    // A real socket in front of the real witness that defers the first N
    // writes — 429 the way the witness's own limiter would, or 503 the way it
    // looks while the machine is restarting mid-deploy.
    proxy = createServer((req, res) => {
      void (async () => {
        const chunks: Buffer[] = [];
        for await (const c of req) chunks.push(c as Buffer);
        if (req.method === 'POST' && deferNext > 0) {
          deferNext--;
          seenDeferrals++;
          res.writeHead(deferStatus, { 'content-type': 'application/json', 'retry-after': '1' });
          res.end(JSON.stringify({ error: deferStatus === 429 ? 'rate limit exceeded for this log_id' : 'restarting' }));
          return;
        }
        const upstream = await fetch(`${witness.url}${req.url}`, {
          method: req.method ?? 'GET',
          headers: { 'content-type': 'application/json' },
          ...(chunks.length ? { body: Buffer.concat(chunks).toString('utf8') } : {}),
        });
        const body = Buffer.from(await upstream.arrayBuffer());
        res.writeHead(upstream.status, { 'content-type': 'application/json' });
        res.end(body);
      })().catch(() => { res.writeHead(500).end(); });
    });
    await new Promise<void>((r) => proxy.listen(0, '127.0.0.1', r));
    proxyUrl = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;
  });

  afterEach(async () => {
    await new Promise<void>((r) => { proxy.close(() => r()); });
    await witness.stop();
  });

  /** A real recorded log with at least one checkpoint waiting to be witnessed. */
  async function recordAndRegister(): Promise<{ cfg: WitnessConfig; key: SigningKeyFile }> {
    generateSigningKey(dir);
    const rec = Recorder.open(dir, { checkpointInterval: 5, fsync: false });
    for (let i = 0; i < 5; i++) {
      await rec.record({
        actor: { human: 'tester', agent_id: 'a', tool: 'vitest' },
        kind: 'tool_call', target: `t-${i}`, args_digest: null,
        payload_ref: null, outcome: 'ok', duration_ms: null,
      });
    }
    await rec.end();
    rec.close();

    const key = generateSigningKey(dir);
    await registerLog(dir, key, { url: proxyUrl });
    return { cfg: readWitnessConfig(dir)!, key };
  }

  for (const status of [429, 503] as const) {
    it(`is deferred twice with ${status}, then succeeds, and writes a real receipt`, async () => {
      const { cfg, key } = await recordAndRegister();
      const pending = pendingSubmissions(dir, readCheckpoints(dir));
      expect(pending.length).toBeGreaterThan(0);

      deferStatus = status;
      deferNext = 2;
      const slept: number[] = [];
      const r = await submitCheckpoint(dir, cfg, key, pending[0]!, undefined, {
        ...DRAIN_RETRY, sleep: async (ms) => { slept.push(ms); },
      });

      expect(seenDeferrals).toBe(2);
      expect(slept).toEqual([1000, 1000]);   // Retry-After: 1, twice
      expect(r.ok, JSON.stringify(r)).toBe(true);
      expect(r.attempts).toBe(3);
      expect(r.transient).toBeUndefined();

      // A real, signed receipt on disk — the submission genuinely went through.
      const receipt = JSON.parse(readFileSync(receiptPath(dir, pending[0]!.index), 'utf8')) as {
        index: number; witness_signature: string;
      };
      expect(receipt.index).toBe(pending[0]!.index);
      expect(receipt.witness_signature.length).toBeGreaterThan(40);
      expect(pendingSubmissions(dir, readCheckpoints(dir)).map((c) => c.index))
        .not.toContain(pending[0]!.index);
    }, 60_000);
  }

  it('`witness submit` exits 0 after a 503, not 2', async () => {
    // Through the real CLI with real sleeps, because the exit code is the
    // thing a script or a CI job actually sees.
    await recordAndRegister();
    deferStatus = 503;
    deferNext = 2;

    const r = await new Promise<{ code: number; stdout: string; stderr: string }>((resolve) => {
      const p = spawn(
        join(process.cwd(), 'node_modules', '.bin', 'tsx'),
        [join(process.cwd(), 'src', 'cli.ts'), 'witness', 'submit', dir],
        { stdio: ['ignore', 'pipe', 'pipe'] },
      );
      let stdout = ''; let stderr = '';
      p.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
      p.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
      p.on('exit', (code) => resolve({ code: code ?? -1, stdout, stderr }));
    });

    expect(seenDeferrals).toBe(2);
    expect(r.code, `stdout:\n${r.stdout}\nstderr:\n${r.stderr}`).toBe(0);
    expect(r.code).not.toBe(2);
    expect(r.stdout).toContain('witnessed');
    expect(pendingSubmissions(dir, readCheckpoints(dir))).toEqual([]);
  }, 60_000);

  it('exits 0 and says deferred when the witness never recovers', async () => {
    // Nothing is wrong with the log, so this must not be reported as a
    // cannot-verify. The checkpoints stay queued.
    await recordAndRegister();
    deferStatus = 503;
    deferNext = 999;

    const r = await new Promise<{ code: number; stdout: string }>((resolve) => {
      const p = spawn(
        join(process.cwd(), 'node_modules', '.bin', 'tsx'),
        [join(process.cwd(), 'src', 'cli.ts'), 'witness', 'submit', dir],
        { stdio: ['ignore', 'pipe', 'pipe'] },
      );
      let stdout = '';
      p.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
      p.stderr.on('data', () => {});
      p.on('exit', (code) => resolve({ code: code ?? -1, stdout }));
    });

    expect(r.code, r.stdout).toBe(0);
    expect(r.stdout).toContain('deferred, still queued');
    expect(r.stdout).toContain('not refused');
    // Still pending, which is the honest outcome.
    expect(pendingSubmissions(dir, readCheckpoints(dir)).length).toBeGreaterThan(0);
  }, 60_000);
});

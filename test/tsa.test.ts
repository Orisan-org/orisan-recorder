import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { buildCheckpoint, generateSigningKey, anchorDigest, type SignedCheckpoint } from '../src/checkpoint.js';
import { derInteger, derSequence } from '../src/der.js';
import {
  anchorCheckpoint, drainAnchorQueue, hasAnchor, listAnchoredSeqs,
  pendingAnchors, readAnchor, type AnchorOptions,
} from '../src/tsa.js';

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'orisan-tsa-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

const h = (s: string) => createHash('sha256').update(s).digest('hex');
const hashes = (n: number, tag = 'e') => [...Array(n).keys()].map((i) => h(`${tag}-${i}`));

/** A syntactically valid TimeStampResp with the given status. */
const fakeResp = (status: number, withToken = true) =>
  derSequence(derSequence(derInteger(status)), ...(withToken ? [derSequence(derInteger(1))] : []));

function fetchReturning(body: Buffer, ok = true, status = 200): NonNullable<AnchorOptions['fetchImpl']> {
  return async () => ({
    ok,
    status,
    arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer,
  });
}

function cpFor(dir_: string, n = 5, from = 0): SignedCheckpoint {
  const kf = generateSigningKey(dir_);
  return buildCheckpoint(hashes(n), from, 'interval', kf);
}

describe('successful anchoring', () => {
  it('stores the .tsr reply and a record naming the submitted digest', async () => {
    const cp = cpFor(dir);
    const r = await anchorCheckpoint(dir, cp, { fetchImpl: fetchReturning(fakeResp(0)), tsaUrl: 'https://tsa.invalid/tsr' });

    expect(r.ok).toBe(true);
    expect(hasAnchor(dir, cp.seq_to)).toBe(true);

    const rec = readAnchor(dir, cp.seq_to)!;
    expect(rec.digest).toBe(anchorDigest(cp).toString('hex'));
    expect(rec.pki_status).toBe(0);
    expect(rec.tsa_url).toBe('https://tsa.invalid/tsr');
    expect(readFileSync(join(dir, rec.tsr_file)).length).toBeGreaterThan(0);
    expect(listAnchoredSeqs(dir)).toEqual([cp.seq_to]);
  });

  it('accepts grantedWithMods', async () => {
    const cp = cpFor(dir);
    expect((await anchorCheckpoint(dir, cp, { fetchImpl: fetchReturning(fakeResp(1)) })).ok).toBe(true);
  });
});

describe('ACCEPTANCE: the TSA is unreachable', () => {
  it('does not throw, does not write an anchor, and explains why', async () => {
    const cp = cpFor(dir);
    const offline: NonNullable<AnchorOptions['fetchImpl']> = async () => {
      throw new Error('getaddrinfo ENOTFOUND tsa.invalid');
    };
    const r = await anchorCheckpoint(dir, cp, { fetchImpl: offline });

    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/TSA unreachable/);
    expect(hasAnchor(dir, cp.seq_to)).toBe(false);
    // Critically: nothing partial is left behind that could be mistaken for proof.
    expect(listAnchoredSeqs(dir)).toEqual([]);
  });

  it('leaves the checkpoint queued, and a later drain anchors it', async () => {
    const cp = cpFor(dir);
    expect(pendingAnchors(dir, [cp])).toHaveLength(1);

    const failed = await drainAnchorQueue(dir, [cp], { fetchImpl: async () => { throw new Error('offline'); } });
    expect(failed[0]!.ok).toBe(false);
    expect(pendingAnchors(dir, [cp])).toHaveLength(1);

    const ok = await drainAnchorQueue(dir, [cp], { fetchImpl: fetchReturning(fakeResp(0)) });
    expect(ok[0]!.ok).toBe(true);
    expect(pendingAnchors(dir, [cp])).toHaveLength(0);
  });

  it('drains only what is still pending', async () => {
    const kf = generateSigningKey(dir);
    const a = buildCheckpoint(hashes(3, 'a'), 0, 'interval', kf);
    const b = buildCheckpoint(hashes(3, 'b'), 3, 'interval', kf);
    await anchorCheckpoint(dir, a, { fetchImpl: fetchReturning(fakeResp(0)) });

    const results = await drainAnchorQueue(dir, [a, b], { fetchImpl: fetchReturning(fakeResp(0)) });
    expect(results).toHaveLength(1);
    expect(results[0]!.seq_to).toBe(b.seq_to);
  });
});

describe('a TSA that answers but refuses', () => {
  it('records no anchor when the status is a rejection', async () => {
    const cp = cpFor(dir);
    const r = await anchorCheckpoint(dir, cp, { fetchImpl: fetchReturning(fakeResp(2, false)) });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/PKIStatus 2/);
    expect(hasAnchor(dir, cp.seq_to)).toBe(false);
  });

  it('records no anchor when granted but no token is present', async () => {
    const cp = cpFor(dir);
    const r = await anchorCheckpoint(dir, cp, { fetchImpl: fetchReturning(fakeResp(0, false)) });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/no token/);
    expect(hasAnchor(dir, cp.seq_to)).toBe(false);
  });

  it('records no anchor on an HTTP error', async () => {
    const cp = cpFor(dir);
    const r = await anchorCheckpoint(dir, cp, { fetchImpl: fetchReturning(Buffer.alloc(0), false, 503) });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/HTTP 503/);
    expect(hasAnchor(dir, cp.seq_to)).toBe(false);
  });

  it('records no anchor when the reply is not parseable DER', async () => {
    const cp = cpFor(dir);
    const r = await anchorCheckpoint(dir, cp, { fetchImpl: fetchReturning(Buffer.from('<html>nope</html>')) });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/malformed TSA response/);
    expect(hasAnchor(dir, cp.seq_to)).toBe(false);
  });
});

describe('this module never judges a TSA signature', () => {
  it('exports nothing that verifies a token', async () => {
    const mod = await import('../src/tsa.js');
    const names = Object.keys(mod).join(' ');
    expect(names).not.toMatch(/verifyToken|verifyTsa|checkSignature/i);
  });
});

describe('regression: a malformed reply must never become an anchor (SECURITY-REVIEW-R1)', () => {
  it('the crafted negative-length response is rejected and the checkpoint stays queued', async () => {
    const cp = cpFor(dir);
    // 16 bytes that used to read as PKIStatus 0 with a token present.
    const evil = Buffer.from('300c3084ffffffff0201003003020105', 'hex');
    const r = await anchorCheckpoint(dir, cp, { fetchImpl: fetchReturning(evil) });

    expect(r.ok).toBe(false);
    expect(hasAnchor(dir, cp.seq_to)).toBe(false);
    // The queue is derived from what is missing, so it must still list this one.
    // Otherwise one bad reply permanently stops us re-asking the real TSA.
    expect(pendingAnchors(dir, [cp])).toHaveLength(1);
  });

  it('a later good reply still anchors it', async () => {
    const cp = cpFor(dir);
    await anchorCheckpoint(dir, cp, { fetchImpl: fetchReturning(Buffer.from('300c3084ffffffff0201003003020105', 'hex')) });
    expect(pendingAnchors(dir, [cp])).toHaveLength(1);
    await anchorCheckpoint(dir, cp, { fetchImpl: fetchReturning(fakeResp(0)) });
    expect(pendingAnchors(dir, [cp])).toHaveLength(0);
  });
});

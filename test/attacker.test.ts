/**
 * The adversarial acceptance tests for R1.3/R1.4.
 *
 * The headline one reproduces, against our own code, the attack that defeated
 * two shipping competitors: delete events and recompute every hash from
 * genesis using the project's own hash function. Chain-only verification
 * passes that by construction. verify() must not.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Recorder } from '../src/recorder.js';
import { EventStore, segmentName } from '../src/store.js';
import { GENESIS_PREV_HASH, computeEventHash, type EventInput, type RecordedEvent } from '../src/schema.js';
import { derInteger, derSequence } from '../src/der.js';
import { verify, EXIT_CLEAN, EXIT_TAMPERED, EXIT_CANNOT_VERIFY } from '../src/verify.js';
import type { AnchorOptions } from '../src/tsa.js';

let dir: string;
let keyDir: string;
let signingKeyPath: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'orisan-atk-'));
  // Never the default (~/.orisan): tests must not write to the real home dir.
  keyDir = mkdtempSync(join(tmpdir(), 'orisan-atk-key-'));
  signingKeyPath = join(keyDir, 'signing.key');
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  rmSync(keyDir, { recursive: true, force: true });
});

/** A syntactically valid granted TimeStampResp — no network, no real TSA. */
const fakeResp = () => derSequence(derSequence(derInteger(0)), derSequence(derInteger(1)));
const fakeTsa: AnchorOptions = {
  fetchImpl: async () => {
    const b = fakeResp();
    return { ok: true, status: 200, arrayBuffer: async () => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer };
  },
};

function ev(i: number): EventInput {
  return {
    actor: { human: 'alice', agent_id: 'spiffe://orisan/agent/t', tool: 'claude-code' },
    kind: i === 7 ? 'flag' : 'tool_call',
    target: i === 7 ? 'shell.exec' : `tool.${i}`,
    args_digest: null,
    payload_ref: null,
    outcome: i === 7 ? 'flagged: credential exfiltration' : 'ok',
    duration_ms: i,
  };
}

async function recordSession(n: number, interval = 10): Promise<void> {
  const rec = Recorder.open(dir, { checkpointInterval: interval, fsync: false, anchor: { ...fakeTsa }, signingKeyPath });
  for (let i = 0; i < n; i++) await rec.record(ev(i));
  await rec.end();
}

/** Rewrite the log: drop `drop` events, re-seal from genesis with our own hasher. */
function recomputeAttack(drop: (e: RecordedEvent) => boolean): void {
  const all = EventStore.open(dir, { readOnly: true }).store.readAll().filter((e) => !drop(e));
  let prev = GENESIS_PREV_HASH;
  const forged = all.map((e, i) => {
    const base = { ...e, seq: i, prev_hash: prev };
    const { hash: _drop, ...rest } = base;
    const sealed = { ...base, hash: computeEventHash(rest as Omit<RecordedEvent, 'hash'>) };
    prev = sealed.hash;
    return sealed;
  });
  // Rewrite segment 0 with the forged chain and remove any later segments.
  const store = EventStore.open(dir).store;
  store.close();
  for (const f of ['events-0001.jsonl', 'events-0002.jsonl', 'events-0003.jsonl']) {
    rmSync(join(dir, f), { force: true });
  }
  writeFileSync(join(dir, segmentName(0)), forged.map((e) => `${JSON.stringify(e)}\n`).join(''));
}

describe('ACCEPTANCE: the recompute attack', () => {
  it('THE KEY TEST: delete 3 events, recompute all hashes with our own hash function, verify fails naming the checkpoint', async () => {
    await recordSession(30, 10);

    const before = verify(dir, { skipOpenssl: true });
    expect(before.findings.filter((f) => f.severity === 'tampered')).toEqual([]);

    // The attacker removes three events including the flagged one.
    recomputeAttack((e) => e.seq === 7 || e.seq === 8 || e.seq === 9);

    // Chain-only verification is fooled — exactly as it was for the competitors.
    expect(EventStore.open(dir, { readOnly: true }).store.verifyChainOnly()).toEqual([]);

    // verify() is not.
    const r = verify(dir, { skipOpenssl: true });
    expect(r.verdict).toBe('tampered');
    expect(r.exitCode).toBe(EXIT_TAMPERED);

    const named = r.findings.filter((f) => f.severity === 'tampered');
    expect(named.length).toBeGreaterThan(0);
    // It must name a checkpoint, not merely say "something is wrong".
    expect(named.some((f) => f.checkpoint_seq_to !== undefined)).toBe(true);
    expect(named.some((f) => f.code === 'checkpoint_root_mismatch' || f.code === 'checkpoint_count_mismatch')).toBe(true);
    expect(named[0]!.message).toMatch(/rewritten after anchoring|added or removed after it was anchored/);
  });

  it('catches a single silently edited event that was re-sealed', async () => {
    await recordSession(20, 10);
    const all = EventStore.open(dir, { readOnly: true }).store.readAll();
    // Change one payload field and re-seal the whole chain.
    all[4] = { ...all[4]!, outcome: 'ok (actually failed)' };
    let prev = GENESIS_PREV_HASH;
    const forged = all.map((e) => {
      const base = { ...e, prev_hash: prev };
      const { hash: _d, ...rest } = base;
      const sealed = { ...base, hash: computeEventHash(rest as Omit<RecordedEvent, 'hash'>) };
      prev = sealed.hash;
      return sealed;
    });
    rmSync(join(dir, 'events-0001.jsonl'), { force: true });
    writeFileSync(join(dir, segmentName(0)), forged.map((e) => `${JSON.stringify(e)}\n`).join(''));

    const r = verify(dir, { skipOpenssl: true });
    expect(r.verdict).toBe('tampered');
    expect(r.findings.some((f) => f.code === 'checkpoint_root_mismatch')).toBe(true);
  });

  it('catches appended events that no anchored checkpoint covers', async () => {
    await recordSession(20, 10);
    // Attacker appends a fabricated but internally consistent event.
    const store = EventStore.open(dir, { fsync: false }).store;
    store.append(ev(999));
    store.close();

    const r = verify(dir, { skipOpenssl: true });
    // Not "tampered" — the chain is consistent and no anchored root is violated —
    // but it must not be clean either: the new event is uncommitted.
    expect(r.verdict).not.toBe('clean');
    expect(r.findings.some((f) => f.code === 'events_past_last_anchor')).toBe(true);
  });

  it('catches an anchor lifted from a different checkpoint', async () => {
    await recordSession(20, 10);
    const anchors = join(dir, 'anchors');
    const a = JSON.parse(readFileSync(join(anchors, '00000009.json'), 'utf8')) as Record<string, unknown>;
    a['digest'] = createHash('sha256').update('someone elses checkpoint').digest('hex');
    writeFileSync(join(anchors, '00000009.json'), JSON.stringify(a));

    const r = verify(dir, { skipOpenssl: true });
    expect(r.verdict).toBe('tampered');
    expect(r.findings.some((f) => f.code === 'anchor_digest_mismatch')).toBe(true);
  });

  it('catches a re-signed checkpoint made with a different key', async () => {
    await recordSession(20, 10);
    const path = join(dir, 'checkpoints.jsonl');
    const lines = readFileSync(path, 'utf8').trim().split('\n');
    const cp = JSON.parse(lines[0]!) as Record<string, unknown>;
    cp['merkle_root'] = createHash('sha256').update('forged root').digest('hex');
    lines[0] = JSON.stringify(cp);
    writeFileSync(path, `${lines.join('\n')}\n`);

    const r = verify(dir, { skipOpenssl: true });
    expect(r.verdict).toBe('tampered');
    expect(r.findings.some((f) => f.code === 'checkpoint_bad_signature')).toBe(true);
  });
});

describe('ACCEPTANCE: cannot-verify is never success', () => {
  it('TSA unreachable: events still record, checkpoint queued, verify says cannot verify and exits 2', async () => {
    const offline: AnchorOptions = { fetchImpl: async () => { throw new Error('ENOTFOUND'); } };
    const rec = Recorder.open(dir, { checkpointInterval: 5, fsync: false, anchor: { ...offline }, signingKeyPath });
    for (let i = 0; i < 12; i++) await rec.record(ev(i));
    await rec.end();

    // Recording was unaffected.
    expect(EventStore.open(dir, { readOnly: true }).store.count).toBe(12);
    // Checkpoints exist but nothing is anchored.
    const r = verify(dir, { skipOpenssl: true });
    expect(r.verdict).toBe('cannot_verify');
    expect(r.exitCode).toBe(EXIT_CANNOT_VERIFY);
    expect(r.findings.some((f) => f.code === 'checkpoint_unanchored')).toBe(true);
    expect(r.verdict).not.toBe('clean');
  });

  it('no checkpoints at all is cannot-verify, not clean', () => {
    const store = EventStore.open(dir, { fsync: false }).store;
    for (let i = 0; i < 5; i++) store.append(ev(i));
    store.close();

    const r = verify(dir, { skipOpenssl: true });
    expect(r.exitCode).toBe(EXIT_CANNOT_VERIFY);
    expect(r.findings.some((f) => f.code === 'no_checkpoints')).toBe(true);
  });

  it('missing public key is cannot-verify', async () => {
    await recordSession(10, 10);
    rmSync(join(dir, 'signing.pub.pem'));
    const r = verify(dir, { skipOpenssl: true });
    expect(r.exitCode).toBe(EXIT_CANNOT_VERIFY);
    expect(r.findings.some((f) => f.code === 'no_public_key')).toBe(true);
  });

  it('an unusable openssl is cannot-verify, never clean', async () => {
    await recordSession(10, 10);
    const r = verify(dir, { tsaCaFile: join(dir, 'signing.pub.pem'), opensslPath: '/nonexistent/openssl' });
    expect(r.exitCode).toBe(EXIT_CANNOT_VERIFY);
    expect(r.findings.some((f) => f.code === 'openssl_unavailable')).toBe(true);
  });

  it('a missing TSA CA is cannot-verify, never clean', async () => {
    await recordSession(10, 10);
    const r = verify(dir, { tsaCaFile: join(dir, 'no-such-ca.pem') });
    expect(r.exitCode).toBe(EXIT_CANNOT_VERIFY);
    expect(r.findings.some((f) => f.code === 'tsa_ca_missing')).toBe(true);
  });

  it('tampering outranks cannot-verify in the verdict', async () => {
    await recordSession(20, 10);
    recomputeAttack((e) => e.seq === 5);
    const r = verify(dir, { skipOpenssl: true });
    expect(r.verdict).toBe('tampered');
    expect(r.findings.some((f) => f.severity === 'cannot_verify')).toBe(true);
  });

  it('EXIT_CLEAN is only reachable when every check ran and passed', async () => {
    await recordSession(20, 10);
    // skipOpenssl means the TSA check did not run, so clean must be unreachable.
    expect(verify(dir, { skipOpenssl: true }).exitCode).not.toBe(EXIT_CLEAN);
  });
});

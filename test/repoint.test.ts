/**
 * `witness repoint` — moving a registered log to a new hostname.
 *
 * The refusals are the feature. A repoint that accepts a different key is a
 * silent re-pin, which turns key pinning into decoration; a repoint to a
 * witness that never saw this log discards the memory the witness existed to
 * keep. Both must refuse, and every test here uses REAL witness instances,
 * because a mock would agree with whatever the client asked it.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Recorder } from '../src/recorder.js';
import { appendCheckpoint, buildCheckpoint, generateSigningKey, loadSigningKey, readCheckpoints } from '../src/checkpoint.js';
import {
  expectedWitnessState, readWitnessConfig, registerLog, repointWitness, submitCheckpoint,
  type WitnessConfig,
} from '../src/witness-service.js';
import { startLocalTsa, type LocalTsa } from './fixtures/tsa-fixture.js';
import { startWitness, type LiveWitness } from './fixtures/witness-fixture.js';

let tsa: LocalTsa;
let home: LiveWitness;      // where the log is registered
let elsewhere: LiveWitness; // a second, genuinely different witness

beforeAll(async () => {
  tsa = startLocalTsa();
  home = await startWitness();
  elsewhere = await startWitness();
}, 90_000);
afterAll(async () => { tsa.cleanup(); await home.stop(); await elsewhere.stop(); });

let dir: string; let ext: string; let keyPath: string; let cfg: WitnessConfig;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'repoint-'));
  ext = mkdtempSync(join(tmpdir(), 'repoint-ext-'));
  keyPath = join(ext, 'signing.key');
});
afterEach(() => { for (const d of [dir, ext]) rmSync(d, { recursive: true, force: true }); });

async function witnessedLog(n = 10, interval = 5): Promise<void> {
  const key = generateSigningKey(dir, keyPath);
  cfg = await registerLog(dir, key, { url: home.url });
  const rec = Recorder.open(dir, {
    checkpointInterval: interval, fsync: false,
    anchor: { ...tsa.anchorOptions }, signingKeyPath: keyPath,
  });
  for (let i = 0; i < n; i++) {
    await rec.record({
      actor: { human: 'alice', agent_id: 'spiffe://x', tool: 'claude-code' },
      kind: 'tool_call', target: `op_${i}`, args_digest: null,
      payload_ref: null, outcome: 'ok', duration_ms: 2,
    });
  }
  await rec.end();
  for (const cp of readCheckpoints(dir)) await submitCheckpoint(dir, cfg, loadSigningKey(dir, keyPath), cp);
}

const repoint = (url: string) => repointWitness(dir, url, readCheckpoints(dir));
const pinnedUrl = () => readWitnessConfig(dir)!.url;

// ---------------------------------------------------------------------------

describe('ATTACK: repoint to an impostor with a different key', () => {
  it('refuses, and says a different key means a different witness', async () => {
    await witnessedLog();
    // A real, working witness — holding this exact log, with every checkpoint —
    // but running its own key. Everything looks right except the signature.
    const key = loadSigningKey(dir, keyPath);
    const impostorCfg = await registerLog(ext, key, { url: elsewhere.url, logId: cfg.log_id });
    for (const cp of readCheckpoints(dir)) {
      expect((await submitCheckpoint(ext, impostorCfg, key, cp)).ok).toBe(true);
    }

    const r = await repoint(elsewhere.url);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal.code).toBe('key_mismatch');
    expect(r.refusal.message).toMatch(/not with the key pinned/i);
    expect(r.refusal.message).toMatch(/different witness/i);
  });

  it('leaves the pinned config completely untouched', async () => {
    await witnessedLog();
    const before = readFileSync(join(dir, 'witness.json'), 'utf8');
    await repoint(elsewhere.url);
    expect(readFileSync(join(dir, 'witness.json'), 'utf8')).toBe(before);
    expect(pinnedUrl()).toBe(home.url);
  });
});

describe('ATTACK: repoint to a witness that has never seen this log', () => {
  it('refuses rather than starting fresh somewhere with no memory', async () => {
    await witnessedLog();
    // elsewhere is running, but knows nothing about this log id.
    const r = await repoint(elsewhere.url);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    // Specifically a 404 on the head, not a connection failure. Accepting
    // either would let a genuine behaviour change hide as a network blip.
    expect(r.refusal.code).toBe('no_record_of_log');
    expect(r.refusal.message).toMatch(/Nothing was changed/);
    expect(pinnedUrl()).toBe(home.url);
  });
});

describe('other refusals', () => {
  it('refuses a witness that is behind, naming what would be lost', async () => {
    await witnessedLog(10, 5);   // two checkpoints
    const key = loadSigningKey(dir, keyPath);

    // A second witness holding only the FIRST checkpoint.
    const partial = await startWitness();
    try {
      // Same signing key AND same witness key is impossible across instances,
      // so drive the check directly: submit only checkpoint 0 there, then
      // repoint using that instance's own pinned config.
      const partialCfg = await registerLog(ext, key, { url: partial.url, logId: cfg.log_id });
      await submitCheckpoint(ext, partialCfg, key, readCheckpoints(dir)[0]!);

      // Pin the partial witness's key so the signature check passes and the
      // BEHIND check is what fires.
      const repinned: WitnessConfig = { ...cfg, witness_pubkey_pem: partial.pubkeyPem };
      const { writeWitnessConfig } = await import('../src/witness-service.js');
      writeWitnessConfig(dir, repinned);

      const r = await repoint(partial.url);
      expect(r.ok).toBe(false);
      if (r.ok) return;
      expect(r.refusal.code).toBe('behind');
      expect(r.refusal.message).toMatch(/silently discard/i);
    } finally { await partial.stop(); }
  });

  it('refuses a witness holding a different summary at the same index', async () => {
    await witnessedLog(5, 5);    // one checkpoint
    const key = loadSigningKey(dir, keyPath);

    const forked = await startWitness();
    try {
      const forkedCfg = await registerLog(ext, key, { url: forked.url, logId: cfg.log_id });
      // Submit a DIFFERENT checkpoint 0 to the other witness.
      const other = buildCheckpoint(
        ['a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64), 'd'.repeat(64), 'e'.repeat(64)],
        0, 'manual', key, null,
      );
      expect((await submitCheckpoint(ext, forkedCfg, key, other)).ok).toBe(true);

      const { writeWitnessConfig } = await import('../src/witness-service.js');
      writeWitnessConfig(dir, { ...cfg, witness_pubkey_pem: forked.pubkeyPem });

      const r = await repoint(forked.url);
      expect(r.ok).toBe(false);
      if (r.ok) return;
      expect(r.refusal.code).toBe('root_mismatch');
      expect(r.refusal.message).toMatch(/fork/i);
    } finally { await forked.stop(); }
  });

  it('refuses an unregistered log and an unreachable host', async () => {
    const bare = await repointWitness(dir, 'https://witness.orisan.org', []);
    expect(bare.ok).toBe(false);
    if (!bare.ok) expect(bare.refusal.code).toBe('not_registered');

    await witnessedLog();
    const dead = await repoint('http://127.0.0.1:1');
    expect(dead.ok).toBe(false);
    if (!dead.ok) expect(dead.refusal.code).toBe('unreachable');
    expect(pinnedUrl()).toBe(home.url);
  });

  it('refuses a pointless repoint to the same url', async () => {
    await witnessedLog();
    const r = await repoint(home.url);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal.code).toBe('same_url');
  });
});

describe('the legitimate move', () => {
  it('accepts the same witness answering at a new address, keeping the key', async () => {
    await witnessedLog();
    const pinnedBefore = readWitnessConfig(dir)!.witness_pubkey_pem;

    // The same instance reached by a different URL — 'localhost' rather than
    // '127.0.0.1'. Same witness, same key, same memory: exactly what a real
    // DNS cutover looks like.
    const movedUrl = home.url.replace('127.0.0.1', 'localhost');
    const r = await repoint(movedUrl);

    expect(r.ok, r.ok ? '' : r.refusal.message).toBe(true);
    if (!r.ok) return;
    expect(r.to).toBe(movedUrl);
    // The key is carried over, never re-learned.
    expect(readWitnessConfig(dir)!.witness_pubkey_pem).toBe(pinnedBefore);
    expect(readWitnessConfig(dir)!.log_id).toBe(cfg.log_id);
    expect(pinnedUrl()).toBe(movedUrl);
  });

  it('allows a move before anything has been witnessed', async () => {
    const key = generateSigningKey(dir, keyPath);
    cfg = await registerLog(dir, key, { url: home.url });
    // Nothing submitted: no memory to preserve, so no state to check.
    expect(expectedWitnessState(dir, readCheckpoints(dir))).toBeNull();
    const r = await repoint(home.url.replace('127.0.0.1', 'localhost'));
    expect(r.ok).toBe(true);
  });
});

describe('expectedWitnessState reads receipts, not intentions', () => {
  it('reflects what the witness confirmed, not what we tried to send', async () => {
    await witnessedLog(10, 5);
    const cps = readCheckpoints(dir);
    const state = expectedWitnessState(dir, cps)!;
    expect(state.index).toBe(cps[cps.length - 1]!.index);
    expect(state.merkle_root).toBe(cps[cps.length - 1]!.merkle_root);

    // An unsubmitted checkpoint must not raise the bar: it has no receipt.
    const extra = buildCheckpoint(['f'.repeat(64)], state.seq_to + 1, 'manual',
      loadSigningKey(dir, keyPath), cps[cps.length - 1]!);
    appendCheckpoint(dir, extra);
    expect(expectedWitnessState(dir, readCheckpoints(dir))!.index).toBe(state.index);
  });
});

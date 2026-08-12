/**
 * The success path, and every confirmed attack from SECURITY-REVIEW-R1.md.
 *
 * Standing rule for this repo: an attack that has ever worked stays in CI
 * forever. The reason five criticals shipped is that nothing here ever reached
 * a clean verdict, so the success path — the only path an attacker cares about
 * — was never exercised.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Recorder } from '../src/recorder.js';
import { EventStore, segmentName } from '../src/store.js';
import { GENESIS_PREV_HASH, computeEventHash, type EventInput, type RecordedEvent } from '../src/schema.js';
import {
  appendCheckpoint, buildCheckpoint, generateSigningKey, loadSigningKey, readCheckpoints, signCheckpoint,
  type CheckpointBody,
} from '../src/checkpoint.js';
import { merkleRoot } from '../src/merkle.js';
import { anchorCheckpoint } from '../src/tsa.js';
import { EXIT_CLEAN, EXIT_TAMPERED, verify } from '../src/verify.js';
import { startLocalTsa, type LocalTsa } from './fixtures/tsa-fixture.js';

let tsa: LocalTsa;
beforeAll(() => { tsa = startLocalTsa(); }, 60_000);
afterAll(() => { tsa.cleanup(); });

let dir: string;
let witnessDir: string;
let witnessFile: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'orisan-attack-'));
  // Deliberately outside `dir`: a witness the operator can rewrite is no witness.
  witnessDir = mkdtempSync(join(tmpdir(), 'orisan-witness-'));
  witnessFile = join(witnessDir, 'witness.jsonl');
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  rmSync(witnessDir, { recursive: true, force: true });
});

function ev(i: number): EventInput {
  return {
    actor: { human: 'alice', agent_id: 'spiffe://orisan/agent/a', tool: 'claude-code' },
    kind: i === 25 ? 'flag' : 'tool_call',
    target: i === 25 ? 'shell.exec' : `tool.${i}`,
    args_digest: null,
    payload_ref: null,
    outcome: i === 25 ? 'flagged: EXFILTRATED ~/.aws/credentials' : 'ok',
    duration_ms: i,
  };
}

/** Record n events with a checkpoint every `interval`, all anchored for real. */
async function honestLog(n = 30, interval = 10): Promise<void> {
  const rec = Recorder.open(dir, {
    checkpointInterval: interval, fsync: false,
    anchor: { ...tsa.anchorOptions }, witnessFile,
  });
  for (let i = 0; i < n; i++) await rec.record(ev(i));
  await rec.end();
}

const run = () => verify(dir, { tsaCaFile: tsa.caFile, witnessFile });

/** A count:0 checkpoint body, as an attacker would hand-craft it. */
function emptyBody(from: number, to: number, keyId: string): CheckpointBody {
  return {
    v: 1, seq_from: from, seq_to: to, count: 0,
    merkle_root: merkleRoot([]),
    created_at: new Date().toISOString(),
    key_id: keyId, reason: 'manual',
  };
}

/** Rewrite the event log with a chain re-sealed from genesis. */
function reseal(events: RecordedEvent[]): void {
  let prev = GENESIS_PREV_HASH;
  const forged = events.map((e, i) => {
    const base = { ...e, seq: i, prev_hash: prev };
    const { hash: _d, ...rest } = base;
    const sealed = { ...base, hash: computeEventHash(rest as Omit<RecordedEvent, 'hash'>) };
    prev = sealed.hash;
    return sealed;
  });
  for (const f of readdirSegments()) rmSync(join(dir, f), { force: true });
  writeFileSync(join(dir, segmentName(0)), forged.map((e) => `${JSON.stringify(e)}\n`).join(''));
}
function readdirSegments(): string[] {
  return require('node:fs').readdirSync(dir).filter((f: string) => /^events-\d+\.jsonl$/.test(f));
}

// ---------------------------------------------------------------------------

describe('the success path', () => {
  it('an honest, fully anchored log verifies CLEAN at exit 0', async () => {
    await honestLog();
    const r = run();
    expect(r.findings).toEqual([]);
    expect(r.verdict).toBe('clean');
    expect(r.exitCode).toBe(EXIT_CLEAN);
    expect(r.events).toBe(30);
    expect(r.checkpoints).toBe(3);
    expect(r.anchored).toBe(3);
    expect(tsa.callCount()).toBeGreaterThan(0);
  });
});

describe('confirmed attacks — each must be caught', () => {
  it('A1: tail truncation — delete trailing events, their checkpoint and its anchors', async () => {
    await honestLog();
    const evs = readFileSync(join(dir, segmentName(0)), 'utf8').trim().split('\n');
    writeFileSync(join(dir, segmentName(0)), evs.slice(0, 20).map((l) => `${l}\n`).join(''));
    const cps = readFileSync(join(dir, 'checkpoints.jsonl'), 'utf8').trim().split('\n');
    writeFileSync(join(dir, 'checkpoints.jsonl'), cps.slice(0, 2).map((l) => `${l}\n`).join(''));
    rmSync(join(dir, 'anchors', '00000029.json'), { force: true });
    rmSync(join(dir, 'anchors', '00000029.tsr'), { force: true });

    const r = run();
    expect(r.exitCode).toBe(EXIT_TAMPERED);
    expect(r.verdict).toBe('tampered');
  });

  it('A2: delete an event, re-seal from genesis, re-anchor with a fresh key', async () => {
    await honestLog();
    const all = EventStore.open(dir).store.readAll().filter((e) => e.kind !== 'flag');
    reseal(all);
    rmSync(join(dir, 'checkpoints.jsonl'), { force: true });
    rmSync(join(dir, 'anchors'), { recursive: true, force: true });
    rmSync(join(dir, 'signing.key'), { force: true });
    rmSync(join(dir, 'signing.pub.pem'), { force: true });

    // Fresh keypair, fresh checkpoint, genuinely anchored — but anchored NOW,
    // long after the events it claims to cover.
    const kf = generateSigningKey(dir);
    const events = EventStore.open(dir).store.readAll();
    const cp = buildCheckpoint(events.map((e) => e.hash), 0, 'manual', kf);
    appendCheckpoint(dir, cp);
    await anchorCheckpoint(dir, cp, tsa.anchorOptions);

    const r = run();
    expect(r.exitCode).toBe(EXIT_TAMPERED);
  });

  it('A3: poison pill — a count:0 checkpoint with a huge seq range', async () => {
    await honestLog(20, 10);
    // Sign with the EXISTING key, not a fresh one: rotating the key would break
    // the honest checkpoints' signatures and get caught for the wrong reason.
    // The real poison pill leaves everything else valid.
    const kf = loadSigningKey(dir);
    // Forged by hand, not via buildCheckpoint: a real attacker writes and signs
    // the JSON directly and is not bound by our API's guard rails.
    const pill = signCheckpoint(emptyBody(1_000_000, 9_000_000, kf.key_id), kf);
    appendCheckpoint(dir, pill);
    await anchorCheckpoint(dir, pill, tsa.anchorOptions);

    const r = run();
    expect(r.exitCode).toBe(EXIT_TAMPERED);
  });

  it('A4: total erasure — zero events plus one count:0 checkpoint', async () => {
    await honestLog(10, 10);
    for (const f of readdirSegments()) rmSync(join(dir, f), { force: true });
    rmSync(join(dir, 'checkpoints.jsonl'), { force: true });
    rmSync(join(dir, 'anchors'), { recursive: true, force: true });
    rmSync(join(dir, 'signing.key'), { force: true });
    rmSync(join(dir, 'signing.pub.pem'), { force: true });

    const kf = generateSigningKey(dir);
    const empty = signCheckpoint(emptyBody(0, -1, kf.key_id), kf);
    appendCheckpoint(dir, empty);
    await anchorCheckpoint(dir, empty, tsa.anchorOptions);

    const r = run();
    expect(r.exitCode).not.toBe(EXIT_CLEAN);
  });

  it('A5: hole — delete a middle checkpoint and its anchor, keep every event', async () => {
    await honestLog();
    const cps = readFileSync(join(dir, 'checkpoints.jsonl'), 'utf8').trim().split('\n');
    writeFileSync(join(dir, 'checkpoints.jsonl'), [cps[0]!, cps[2]!].map((l) => `${l}\n`).join(''));
    rmSync(join(dir, 'anchors', '00000019.json'), { force: true });
    rmSync(join(dir, 'anchors', '00000019.tsr'), { force: true });

    const r = run();
    expect(r.exitCode).toBe(EXIT_TAMPERED);
    expect(readCheckpoints(dir)).toHaveLength(2);
  });
});

describe('the witness', () => {
  it('a clean log needs one: without it, verify cannot reach exit 0', async () => {
    await honestLog();
    const r = verify(dir, { tsaCaFile: tsa.caFile });
    expect(r.exitCode).not.toBe(EXIT_CLEAN);
    expect(r.findings.some((f) => f.code === 'no_witness')).toBe(true);
  });

  it('a witness kept inside the log directory is not counted', async () => {
    const inside = join(dir, 'witness.jsonl');
    const rec = Recorder.open(dir, {
      checkpointInterval: 10, fsync: false,
      anchor: { ...tsa.anchorOptions }, witnessFile: inside,
    });
    for (let i = 0; i < 20; i++) await rec.record(ev(i));
    await rec.end();

    const r = verify(dir, { tsaCaFile: tsa.caFile, witnessFile: inside });
    expect(r.exitCode).not.toBe(EXIT_CLEAN);
    expect(r.findings.some((f) => f.code === 'witness_inside_log_dir')).toBe(true);
  });

  it('detects a checkpoint rewritten after it was witnessed', async () => {
    await honestLog(20, 10);
    // Re-sign checkpoint 1 over a different range, keeping the log self-consistent.
    const kf = loadSigningKey(dir);
    const cps = readCheckpoints(dir);
    const forged = signCheckpoint({ ...cps[1]!, created_at: new Date(0).toISOString() }, kf);
    writeFileSync(join(dir, 'checkpoints.jsonl'),
      [cps[0]!, forged].map((c) => `${JSON.stringify(c)}\n`).join(''));

    const r = verify(dir, { tsaCaFile: tsa.caFile, witnessFile });
    expect(r.exitCode).toBe(EXIT_TAMPERED);
    expect(r.findings.some((f) => f.code === 'witness_link_mismatch')).toBe(true);
  });
});

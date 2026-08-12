/**
 * W1.6 — the attack tests. Tier C: these results are the definition of done.
 *
 * Every one runs against a REAL witness service in-process, not a mock. A mock
 * agrees with whatever the client expects, which is exactly the assumption
 * these tests exist to remove.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Recorder } from '../src/recorder.js';
import { EventStore, segmentName } from '../src/store.js';
import { GENESIS_PREV_HASH, canonicalJson, computeEventHash, type EventInput, type RecordedEvent } from '../src/schema.js';
import {
  appendCheckpoint, buildCheckpoint, generateSigningKey, loadSigningKey, readCheckpoints,
} from '../src/checkpoint.js';
import {
  fetchHead, registerLog, submitCheckpoint, WitnessKeyMismatch,
  type WitnessConfig, type FetchLike,
} from '../src/witness-service.js';
import { EXIT_CANNOT_VERIFY, EXIT_CLEAN, EXIT_TAMPERED, verify, type WitnessServiceInput } from '../src/verify.js';
import { startLocalTsa, type LocalTsa } from './fixtures/tsa-fixture.js';
import { startWitness, type LiveWitness } from './fixtures/witness-fixture.js';

let tsa: LocalTsa;
let wit: LiveWitness;
beforeAll(async () => { tsa = startLocalTsa(); wit = await startWitness(); }, 90_000);
afterAll(async () => { tsa.cleanup(); await wit.stop(); });

let dir: string; let ext: string; let keyPath: string; let cfg: WitnessConfig;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'w1-'));
  ext = mkdtempSync(join(tmpdir(), 'w1-ext-'));
  keyPath = join(ext, 'signing.key');
});
afterEach(() => { for (const d of [dir, ext]) rmSync(d, { recursive: true, force: true }); });

function ev(i: number): EventInput {
  return {
    actor: { human: 'alice', agent_id: 'spiffe://orisan/a', tool: 'claude-code' },
    kind: i === 25 ? 'flag' : 'tool_call',
    target: i === 25 ? 'shell.exec' : `tool.${i}`,
    args_digest: null, payload_ref: null,
    outcome: i === 25 ? 'flagged: EXFILTRATED ~/.aws/credentials' : 'ok',
    duration_ms: i,
  };
}

/** Record n events, anchor each checkpoint, and submit each to the live witness. */
async function honestLog(n = 30, interval = 10): Promise<void> {
  const key = generateSigningKey(dir, keyPath);
  cfg = await registerLog(dir, key, { url: wit.url });
  const rec = Recorder.open(dir, {
    checkpointInterval: interval, fsync: false,
    anchor: { ...tsa.anchorOptions }, signingKeyPath: keyPath,
  });
  for (let i = 0; i < n; i++) await rec.record(ev(i));
  await rec.end();
  for (const cp of readCheckpoints(dir)) {
    const r = await submitCheckpoint(dir, cfg, key, cp);
    expect(r.ok, `submit ${cp.index}: ${r.error ?? ''}`).toBe(true);
  }
}

async function witnessInput(override?: Partial<WitnessServiceInput>, fetchImpl?: FetchLike): Promise<WitnessServiceInput> {
  const fetched = await fetchHead(cfg, fetchImpl);
  return {
    logId: cfg.log_id, url: cfg.url,
    reachable: fetched.reachable,
    ...(fetched.error !== undefined ? { error: fetched.error } : {}),
    ...(fetched.head !== undefined ? { head: fetched.head } : {}),
    ...(fetched.signatureValid !== undefined ? { signatureValid: fetched.signatureValid } : {}),
    ...override,
  };
}

const run = async (over?: Partial<WitnessServiceInput>, f?: FetchLike) =>
  verify(dir, { tsaCaFile: tsa.caFile, witnessService: await witnessInput(over, f) });

// ---------------------------------------------------------------------------

describe('the truthful clean', () => {
  it('an honest, anchored, witnessed log is CLEAN at exit 0', async () => {
    await honestLog();
    const r = await run();
    expect(r.findings).toEqual([]);
    expect(r.verdict).toBe('clean');
    expect(r.exitCode).toBe(EXIT_CLEAN);
  });
});

describe('W1: local truncation', () => {
  it('THE A1 KILL: deleting events + checkpoint + anchors is caught, naming the missing index', async () => {
    await honestLog();
    // The full R1 A1 attack: remove the tail everywhere locally.
    const evs = readFileSync(join(dir, segmentName(0)), 'utf8').trim().split('\n');
    writeFileSync(join(dir, segmentName(0)), evs.slice(0, 20).map((l) => `${l}\n`).join(''));
    const cps = readFileSync(join(dir, 'checkpoints.jsonl'), 'utf8').trim().split('\n');
    writeFileSync(join(dir, 'checkpoints.jsonl'), cps.slice(0, 2).map((l) => `${l}\n`).join(''));
    rmSync(join(dir, 'anchors', '00000029.json'), { force: true });
    rmSync(join(dir, 'anchors', '00000029.tsr'), { force: true });
    rmSync(join(dir, 'receipts', '00000002.json'), { force: true });

    const r = await run();
    expect(r.exitCode).toBe(EXIT_TAMPERED);
    const f = r.findings.find((x) => x.code === 'truncation_detected');
    expect(f).toBeDefined();
    expect(f!.message).toMatch(/checkpoint\(s\) 2/);
  });
});

describe('W2: re-seal from genesis and try to re-register', () => {
  it('the witness refuses the fork with 409 and verify reports fork_detected', async () => {
    await honestLog(20, 10);
    const key = loadSigningKey(dir, keyPath);

    // Remove an event from INSIDE checkpoint 0's range. Dropping a later event
    // would leave checkpoint 0 byte-identical, and the witness would rightly
    // treat the re-submission as a harmless retry rather than a fork.
    const kept = EventStore.open(dir, { readOnly: true }).store.readAll().filter((e) => e.seq !== 3);
    let prev = GENESIS_PREV_HASH;
    const forged = kept.map((e, i) => {
      const base = { ...e, seq: i, prev_hash: prev };
      const { hash: _d, ...rest } = base;
      const sealed = { ...base, hash: computeEventHash(rest as Omit<RecordedEvent, 'hash'>) };
      prev = sealed.hash;
      return sealed;
    });
    writeFileSync(join(dir, segmentName(0)), forged.map((e) => `${JSON.stringify(e)}\n`).join(''));
    rmSync(join(dir, 'checkpoints.jsonl'), { force: true });
    const cp = buildCheckpoint(forged.slice(0, 10).map((e) => e.hash), 0, 'manual', key, null);
    appendCheckpoint(dir, cp);

    const submit = await submitCheckpoint(dir, cfg, key, cp);
    expect(submit.ok).toBe(false);
    expect(submit.status).toBe(409);
    expect(submit.conflict).toBe(true);

    const r = await run();
    expect(r.exitCode).toBe(EXIT_TAMPERED);
    expect(r.findings.some((x) => x.code === 'fork_detected')).toBe(true);
  });

  it('re-registering the same log_id with a fresh key is refused by the witness', async () => {
    await honestLog(10, 10);
    rmSync(keyPath, { force: true });
    const fresh = generateSigningKey(dir, keyPath);
    await expect(registerLog(dir, fresh, { url: wit.url, logId: cfg.log_id })).rejects.toThrow(/409|different signing key/);
  });
});

describe('W3: a substituted witness', () => {
  it('a different key on the head is an attack, not a gap', async () => {
    await honestLog(10, 10);
    // Same shape of response, signed by somebody else entirely.
    const impostor = await startWitness();
    try {
      // A convincing impostor: it holds the same log and the same checkpoints,
      // and answers a perfectly well-formed head — signed with ITS key.
      const key = loadSigningKey(dir, keyPath);
      const impostorCfg = await registerLog(ext, key, { url: impostor.url, logId: cfg.log_id });
      for (const cp of readCheckpoints(dir)) {
        expect((await submitCheckpoint(ext, impostorCfg, key, cp)).ok).toBe(true);
      }

      // Point at the impostor but keep the PINNED key. fetchHead does the
      // signature check itself; nothing here is asserted by hand.
      const badCfg: WitnessConfig = { ...cfg, url: impostor.url };
      const fetched = await fetchHead(badCfg);
      expect(fetched.reachable).toBe(true);
      expect(fetched.signatureValid).toBe(false);

      const r = verify(dir, {
        tsaCaFile: tsa.caFile,
        witnessService: {
          logId: cfg.log_id, url: impostor.url,
          reachable: true,
          ...(fetched.head !== undefined ? { head: fetched.head } : {}),
          ...(fetched.signatureValid !== undefined ? { signatureValid: fetched.signatureValid } : {}),
        },
      });
      expect(r.exitCode).toBe(EXIT_TAMPERED);
      expect(r.findings.some((x) => x.code === 'witness_signature_invalid')).toBe(true);
    } finally {
      await impostor.stop();
    }
  });

  it('a receipt signed by the wrong key throws WitnessKeyMismatch, never re-pins', async () => {
    await honestLog(10, 10);
    const key = loadSigningKey(dir, keyPath);
    const other = generateKeyPairSync('ed25519');
    const cp = readCheckpoints(dir)[0]!;

    // A witness that returns a well-formed receipt signed by a key we did not pin.
    const evilFetch: FetchLike = async () => ({
      ok: true, status: 200,
      json: async () => ({
        log_id: cfg.log_id, index: 99, seq_from: 0, seq_to: 9,
        merkle_root: cp.merkle_root, witnessed_at: new Date().toISOString(),
        witness_signature: edSign(null, Buffer.from(canonicalJson({ x: 1 }), 'utf8'), other.privateKey).toString('base64'),
      }),
      text: async () => '',
    });

    await expect(submitCheckpoint(dir, cfg, key, cp, evilFetch)).rejects.toBeInstanceOf(WitnessKeyMismatch);
    // And the pinned key is untouched.
    const onDisk = JSON.parse(readFileSync(join(dir, 'witness.json'), 'utf8')) as WitnessConfig;
    expect(onDisk.witness_pubkey_pem).toBe(cfg.witness_pubkey_pem);
  });
});

describe('W4: the witness is offline', () => {
  it('exit 2, never 0, and never an accusation', async () => {
    await honestLog(10, 10);
    const dead: FetchLike = async () => { throw new Error('ECONNREFUSED'); };
    const r = await run(undefined, dead);
    expect(r.exitCode).toBe(EXIT_CANNOT_VERIFY);
    expect(r.verdict).toBe('cannot_verify');
    const f = r.findings.find((x) => x.code === 'witness_unreachable');
    expect(f).toBeDefined();
    expect(f!.severity).toBe('cannot_verify');
    expect(r.findings.some((x) => x.severity === 'tampered')).toBe(false);
  });
});

describe('W5: a forged head', () => {
  it('a valid-looking head with a bad signature is exit 1', async () => {
    await honestLog(10, 10);
    const r = await run({ signatureValid: false });
    expect(r.exitCode).toBe(EXIT_TAMPERED);
    expect(r.findings.some((x) => x.code === 'witness_signature_invalid')).toBe(true);
  });

  it('a head for a different log_id is exit 1', async () => {
    await honestLog(10, 10);
    const head = (await witnessInput()).head!;
    const r = await run({ head: { ...head, log_id: '00000000-0000-4000-8000-000000000000' }, signatureValid: true });
    expect(r.exitCode).toBe(EXIT_TAMPERED);
    expect(r.findings.some((x) => x.code === 'witness_wrong_log')).toBe(true);
  });

  it('a head whose merkle_root disagrees with the local checkpoint is exit 1', async () => {
    await honestLog(10, 10);
    const head = (await witnessInput()).head!;
    const r = await run({ head: { ...head, merkle_root: 'f'.repeat(64) }, signatureValid: true });
    expect(r.exitCode).toBe(EXIT_TAMPERED);
    expect(r.findings.some((x) => x.code === 'witness_mismatch')).toBe(true);
  });
});

describe('unwitnessed checkpoints are a gap, not an accusation', () => {
  it('a local checkpoint never submitted is cannot_verify', async () => {
    await honestLog(10, 10);
    const key = loadSigningKey(dir, keyPath);
    // submitToWitness:false simulates the queue not having drained — the
    // recorder normally submits automatically, so this is the offline case.
    const rec = Recorder.open(dir, {
      checkpointInterval: 5, fsync: false, anchor: { ...tsa.anchorOptions },
      signingKeyPath: keyPath, submitToWitness: false,
    });
    for (let i = 10; i < 15; i++) await rec.record(ev(i));
    await rec.end();
    void key;

    const r = await run();
    expect(r.exitCode).toBe(EXIT_CANNOT_VERIFY);
    expect(r.findings.some((x) => x.code === 'checkpoints_not_witnessed')).toBe(true);
    expect(r.findings.some((x) => x.severity === 'tampered')).toBe(false);
  });
});

describe('the five R1 attacks, re-run with a witness configured', () => {
  it('A1 tail truncation', async () => {
    await honestLog();
    const evs = readFileSync(join(dir, segmentName(0)), 'utf8').trim().split('\n');
    writeFileSync(join(dir, segmentName(0)), evs.slice(0, 20).map((l) => `${l}\n`).join(''));
    const cps = readFileSync(join(dir, 'checkpoints.jsonl'), 'utf8').trim().split('\n');
    writeFileSync(join(dir, 'checkpoints.jsonl'), cps.slice(0, 2).map((l) => `${l}\n`).join(''));
    rmSync(join(dir, 'anchors'), { recursive: true, force: true });
    expect((await run()).exitCode).toBe(EXIT_TAMPERED);
  });

  it('A2 delete an event, re-seal, re-anchor', async () => {
    await honestLog(20, 10);
    const kept = EventStore.open(dir, { readOnly: true }).store.readAll().filter((e) => e.seq !== 3);
    let prev = GENESIS_PREV_HASH;
    const forged = kept.map((e, i) => {
      const base = { ...e, seq: i, prev_hash: prev };
      const { hash: _d, ...rest } = base;
      const sealed = { ...base, hash: computeEventHash(rest as Omit<RecordedEvent, 'hash'>) };
      prev = sealed.hash;
      return sealed;
    });
    writeFileSync(join(dir, segmentName(0)), forged.map((e) => `${JSON.stringify(e)}\n`).join(''));
    expect((await run()).exitCode).toBe(EXIT_TAMPERED);
  });

  it('A3 poison pill (count:0 over a huge range)', async () => {
    await honestLog(20, 10);
    const key = loadSigningKey(dir, keyPath);
    const cps = readCheckpoints(dir);
    const { signCheckpoint } = await import('../src/checkpoint.js');
    const { merkleRoot } = await import('../src/merkle.js');
    const pill = signCheckpoint({
      v: 2, index: cps.length, prev_checkpoint_hash: '0'.repeat(64),
      seq_from: 1_000_000, seq_to: 9_000_000, count: 0,
      merkle_root: merkleRoot([]), created_at: new Date().toISOString(),
      key_id: key.key_id, reason: 'manual',
    }, key);
    appendCheckpoint(dir, pill);
    expect((await run()).exitCode).toBe(EXIT_TAMPERED);
  });

  it('A4 total erasure', async () => {
    await honestLog(10, 10);
    rmSync(join(dir, segmentName(0)), { force: true });
    rmSync(join(dir, 'checkpoints.jsonl'), { force: true });
    rmSync(join(dir, 'anchors'), { recursive: true, force: true });
    const r = await run();
    expect(r.exitCode).toBe(EXIT_TAMPERED);
    // The witness still remembers, which is the whole point.
    expect(r.findings.some((x) => x.code === 'truncation_detected')).toBe(true);
  });

  it('A5 hole in the middle', async () => {
    await honestLog();
    const cps = readFileSync(join(dir, 'checkpoints.jsonl'), 'utf8').trim().split('\n');
    writeFileSync(join(dir, 'checkpoints.jsonl'), [cps[0]!, cps[2]!].map((l) => `${l}\n`).join(''));
    expect((await run()).exitCode).toBe(EXIT_TAMPERED);
  });
});

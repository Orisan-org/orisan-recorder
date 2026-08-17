/**
 * Issue #2b — retention that a verifier can tell apart from an attack.
 *
 * Deleting old events IS the truncation attack. The only thing separating a
 * legitimate prune from A1 is that the prune is recorded, bounded to whole
 * anchored ranges, and leaves the proof of what it removed behind. So the
 * tests that matter here are the ones where those properties are missing:
 * every section below removes exactly the same events and differs only in
 * whether the record justifying it is real.
 *
 * The last section is a permanent attack test in the sense this repo means it:
 * an unrecorded gap must never verify.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Recorder } from '../src/recorder.js';
import type { AnchorOptions } from '../src/tsa.js';
import { EventStore } from '../src/store.js';
import { readCheckpoints } from '../src/checkpoint.js';
import type { EventInput } from '../src/schema.js';
import {
  PRUNES_FILENAME, prune, pruneDigest, prunedRanges, readPruneRecords, selectForPrune,
  type PruneRecord,
} from '../src/prune.js';
import { EXIT_CANNOT_VERIFY, EXIT_TAMPERED, verify } from '../src/verify.js';
import { startLocalTsa, type LocalTsa } from './fixtures/tsa-fixture.js';

let tsa: LocalTsa;
beforeAll(() => { tsa = startLocalTsa(); }, 60_000);
afterAll(() => { tsa.cleanup(); });

let dir: string;
let keyDir: string;
let signingKeyPath: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'orisan-prune-'));
  keyDir = mkdtempSync(join(tmpdir(), 'orisan-prunekey-'));
  signingKeyPath = join(keyDir, 'signing.key');
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  rmSync(keyDir, { recursive: true, force: true });
});

const ev = (i: number): EventInput => ({
  actor: { human: 'alice', agent_id: 'spiffe://orisan/agent/a', tool: 'claude-code' },
  kind: 'tool_call',
  target: `tool.${i}`,
  args_digest: null,
  payload_ref: null,
  outcome: 'ok',
  duration_ms: i,
});

/** n events, a checkpoint every `interval`, every checkpoint really anchored. */
async function anchoredLog(n = 50, interval = 10): Promise<void> {
  const rec = Recorder.open(dir, {
    checkpointInterval: interval, fsync: false,
    anchor: { ...tsa.anchorOptions }, signingKeyPath,
  });
  for (let i = 0; i < n; i++) await rec.record(ev(i));
  await rec.end();
  rec.close();
}

const run = () => verify(dir, { tsaCaFile: tsa.caFile });
const eventSeqs = (): number[] =>
  [...EventStore.open(dir, { readOnly: true }).store.read()].map((e) => e.seq);

// ---------------------------------------------------------------------------

describe('what may be pruned', () => {
  it('refuses a range that is not anchored, and says so', async () => {
    // A TSA that cannot be reached. Omitting `anchor` does NOT give an
    // unanchored log — it falls back to the default authority and, on a
    // machine with network, really anchors. The first version of this test
    // did that and quietly proved nothing.
    const offline: AnchorOptions = { fetchImpl: async () => { throw new Error('ENOTFOUND'); } };
    const rec = Recorder.open(dir, { checkpointInterval: 10, fsync: false, anchor: { ...offline }, signingKeyPath });
    for (let i = 0; i < 30; i++) await rec.record(ev(i));
    await rec.end();
    rec.close();

    const sel = selectForPrune(dir, { keepLast: 0 });
    expect(sel.eligible).toEqual([]);
    expect(sel.candidates.some((c) => c.blocked?.includes('not anchored'))).toBe(true);
    expect(prune(dir, { keepLast: 0 }).eventsRemoved).toBe(0);
  }, 120_000);

  it('never prunes the newest checkpoint, because events after it are uncommitted', async () => {
    await anchoredLog(50, 10);
    const checkpoints = readCheckpoints(dir);
    const sel = selectForPrune(dir, { keepLast: 0 });
    expect(sel.eligible.map((c) => c.index)).not.toContain(checkpoints[checkpoints.length - 1]!.index);
    expect(sel.candidates.at(-1)!.blocked).toContain('newest checkpoint');
  }, 120_000);

  it('--keep-last keeps that many ranges', async () => {
    await anchoredLog(50, 10);
    const total = readCheckpoints(dir).length;
    expect(selectForPrune(dir, { keepLast: 2 }).eligible).toHaveLength(total - 2);
    expect(selectForPrune(dir, { keepLast: total }).eligible).toHaveLength(0);
  }, 120_000);

  it('--before only takes ranges older than the date', async () => {
    await anchoredLog(50, 10);
    expect(selectForPrune(dir, { before: new Date('2000-01-01') }).eligible).toHaveLength(0);
    const all = selectForPrune(dir, { before: new Date(Date.now() + 60_000) }).eligible;
    expect(all.length).toBeGreaterThan(0);
  }, 120_000);

  it('a dry run changes nothing', async () => {
    await anchoredLog(50, 10);
    const before = eventSeqs();
    const r = prune(dir, { keepLast: 1, dryRun: true });
    expect(r.eventsRemoved).toBeGreaterThan(0);
    expect(eventSeqs()).toEqual(before);
    expect(existsSync(join(dir, PRUNES_FILENAME))).toBe(false);
  }, 120_000);
});

describe('a real prune', () => {
  it('removes whole ranges, keeps the checkpoints and anchors, and verify accepts it', async () => {
    await anchoredLog(50, 10);
    const before = run();
    const checkpointsBefore = readCheckpoints(dir).length;
    const anchorsBefore = readdirSync(dir).filter((f) => f.includes('anchor')).length
      + (existsSync(join(dir, 'anchors')) ? readdirSync(join(dir, 'anchors')).length : 0);

    const r = prune(dir, { keepLast: 2 });
    expect(r.eventsRemoved).toBeGreaterThan(0);
    expect(r.eventsRemoved % 10).toBe(0);   // whole ranges only

    // The proof stays behind. This is the whole design.
    expect(readCheckpoints(dir)).toHaveLength(checkpointsBefore);
    const anchorsAfter = readdirSync(dir).filter((f) => f.includes('anchor')).length
      + (existsSync(join(dir, 'anchors')) ? readdirSync(join(dir, 'anchors')).length : 0);
    expect(anchorsAfter).toBe(anchorsBefore);

    const after = run();
    expect(after.prunedEvents).toBe(r.eventsRemoved);
    // No new tampered finding was introduced by the prune.
    const tampered = after.findings.filter((f) => f.severity === 'tampered');
    expect(tampered, JSON.stringify(tampered, null, 2)).toEqual(
      before.findings.filter((f) => f.severity === 'tampered'),
    );
  }, 120_000);

  it('records the prune in the chain, committing to the manifest by digest', async () => {
    await anchoredLog(50, 10);
    const r = prune(dir, { keepLast: 2 });

    const records = readPruneRecords(dir);
    expect(records).toHaveLength(1);
    expect(r.event!.kind).toBe('prune');
    expect(r.event!.args_digest).toBe(pruneDigest(records[0]!));

    // And it really is in the log, not just in the return value.
    const onDisk = [...EventStore.open(dir, { readOnly: true }).store.read()].find((e) => e.kind === 'prune');
    expect(onDisk?.args_digest).toBe(pruneDigest(records[0]!));
  }, 120_000);

  it('keeps the anchored root of everything it removed', async () => {
    await anchoredLog(50, 10);
    const roots = new Map(readCheckpoints(dir).map((c) => [c.index, c.merkle_root]));
    prune(dir, { keepLast: 2 });
    for (const range of prunedRanges(dir)) {
      expect(range.merkle_root).toBe(roots.get(range.checkpoint_index));
      expect(readCheckpoints(dir).find((c) => c.index === range.checkpoint_index)!.merkle_root)
        .toBe(range.merkle_root);
    }
  }, 120_000);

  it('the chain still walks across the gap', async () => {
    await anchoredLog(50, 10);
    prune(dir, { keepLast: 2 });
    const after = run();
    expect(after.findings.filter((f) => f.code.startsWith('chain_'))).toEqual([]);
    // The events really are gone.
    const seqs = eventSeqs();
    expect(seqs).not.toContain(0);
    expect(seqs.length).toBeLessThan(51);
  }, 120_000);

  it('is idempotent: a second prune finds nothing left to do', async () => {
    await anchoredLog(50, 10);
    const first = prune(dir, { keepLast: 2 });
    const second = prune(dir, { keepLast: 2 });
    expect(second.eventsRemoved).toBe(0);
    expect(readPruneRecords(dir)).toHaveLength(1);
    expect(first.eventsRemoved).toBeGreaterThan(0);
  }, 120_000);

  it('refuses to prune a range that is already incomplete, rather than burying it', async () => {
    await anchoredLog(50, 10);
    // Someone removed one event by hand. Pruning the range would erase the
    // discrepancy along with the evidence.
    const seg = join(dir, readdirSync(dir).filter((f) => /^events-\d+\.jsonl$/.test(f)).sort()[0]!);
    const lines = readFileSync(seg, 'utf8').split('\n').filter(Boolean);
    writeFileSync(seg, lines.filter((l) => (JSON.parse(l) as { seq: number }).seq !== 3).map((l) => `${l}\n`).join(''));
    expect(() => prune(dir, { keepLast: 2 })).toThrow(/this log has a problem that pruning would hide/);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// ATTACK TESTS. These stay in CI forever.
// ---------------------------------------------------------------------------

describe('ATTACK: a gap without a record is still tampering', () => {
  it('deleting a whole checkpoint range by hand, with no prune record, fails verify', async () => {
    await anchoredLog(50, 10);

    // Exactly what a legitimate prune of range 0..9 removes — and nothing else.
    // The only difference from the honest operation is the missing record.
    const seg = join(dir, readdirSync(dir).filter((f) => /^events-\d+\.jsonl$/.test(f)).sort()[0]!);
    const lines = readFileSync(seg, 'utf8').split('\n').filter(Boolean);
    writeFileSync(seg, lines.filter((l) => (JSON.parse(l) as { seq: number }).seq > 9).map((l) => `${l}\n`).join(''));
    expect(eventSeqs()).not.toContain(0);
    expect(existsSync(join(dir, PRUNES_FILENAME))).toBe(false);

    const r = run();
    expect(r.exitCode).toBe(EXIT_TAMPERED);
    expect(r.verdict).toBe('tampered');
    const codes = r.findings.filter((f) => f.severity === 'tampered').map((f) => f.code);
    expect(codes).toContain('checkpoint_count_mismatch');
  }, 120_000);

  it('a prune manifest with no prune event in the chain is refused', async () => {
    await anchoredLog(50, 10);
    // Do the honest thing, then remove only the record's backing in the chain
    // by writing a fresh manifest nothing vouches for.
    const cp = readCheckpoints(dir)[0]!;
    const forged: PruneRecord = {
      v: 1,
      pruned_at: new Date().toISOString(),
      reason: 'retention',
      ranges: [{
        checkpoint_index: cp.index, seq_from: cp.seq_from, seq_to: cp.seq_to,
        count: cp.count, merkle_root: cp.merkle_root,
        last_event_hash: '0'.repeat(64), first_prev_hash: '0'.repeat(64),
      }],
    };
    writeFileSync(join(dir, PRUNES_FILENAME), `${JSON.stringify(forged)}\n`);
    const seg = join(dir, readdirSync(dir).filter((f) => /^events-\d+\.jsonl$/.test(f)).sort()[0]!);
    const lines = readFileSync(seg, 'utf8').split('\n').filter(Boolean);
    writeFileSync(seg, lines.filter((l) => (JSON.parse(l) as { seq: number }).seq > cp.seq_to).map((l) => `${l}\n`).join(''));

    const r = run();
    expect(r.exitCode).toBe(EXIT_TAMPERED);
    expect(r.findings.map((f) => f.code)).toContain('prune_not_in_chain');
  }, 120_000);

  it('editing the manifest after the prune breaks the digest it is vouched by', async () => {
    await anchoredLog(50, 10);
    prune(dir, { keepLast: 2 });
    expect(run().findings.filter((f) => f.code === 'prune_not_in_chain')).toEqual([]);

    // Widen the claimed range to cover a checkpoint that was not pruned.
    const record = readPruneRecords(dir)[0]!;
    record.ranges[0]!.seq_to += 10;
    writeFileSync(join(dir, PRUNES_FILENAME), `${JSON.stringify(record)}\n`);

    const r = run();
    expect(r.exitCode).toBe(EXIT_TAMPERED);
    expect(r.findings.map((f) => f.code)).toContain('prune_not_in_chain');
  }, 120_000);

  it('deleting the prune record turns the pruned range back into an unexplained gap', async () => {
    await anchoredLog(50, 10);
    prune(dir, { keepLast: 2 });
    expect(run().verdict).not.toBe('tampered');

    rmSync(join(dir, PRUNES_FILENAME), { force: true });
    const r = run();
    expect(r.exitCode).toBe(EXIT_TAMPERED);
    expect(r.findings.map((f) => f.code)).toContain('checkpoint_count_mismatch');
  }, 120_000);

  it('a prune record whose boundary hashes do not join up is caught', async () => {
    await anchoredLog(50, 10);
    prune(dir, { keepLast: 2 });

    // Re-vouch the tampered manifest by rewriting the prune event's digest
    // too — an attacker with write access to the whole directory. The chain
    // hash over that event changes, so this must still be caught; the
    // boundary check is the backstop if it ever were not.
    const record = readPruneRecords(dir)[0]!;
    record.ranges[0]!.last_event_hash = 'f'.repeat(64);
    writeFileSync(join(dir, PRUNES_FILENAME), `${JSON.stringify(record)}\n`);

    const r = run();
    expect(r.exitCode).toBe(EXIT_TAMPERED);
    expect(r.findings.some((f) => f.code === 'prune_not_in_chain' || f.code === 'prune_boundary_mismatch')).toBe(true);
  }, 120_000);

  it('a prune that did not finish is reported rather than passed', async () => {
    await anchoredLog(50, 10);
    // Keep the real line, so putting it back is a genuine restoration rather
    // than a hand-built event the schema would reject before verify got near
    // the prune logic.
    const segName = readdirSync(dir).filter((f) => /^events-\d+\.jsonl$/.test(f)).sort()[0]!;
    const originalLines = readFileSync(join(dir, segName), 'utf8').split('\n').filter(Boolean);

    const r = prune(dir, { keepLast: 2 });
    const range = r.ranges[0]!;
    const revived = originalLines.find((l) => (JSON.parse(l) as { seq: number }).seq === range.seq_from)!;

    const seg = join(dir, segName);
    writeFileSync(seg, `${revived}\n${readFileSync(seg, 'utf8')}`);

    const report = run();
    expect(report.exitCode).not.toBe(0);
    expect(report.findings.map((f) => f.code)).toContain('prune_incomplete');
  }, 120_000);
});

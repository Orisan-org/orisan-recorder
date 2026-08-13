/** R4 — "Prove it" runs the real attack on the user's own log. */
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Recorder } from '../src/recorder.js';
import { prove } from '../src/prove.js';
import { startLocalTsa, type LocalTsa } from './fixtures/tsa-fixture.js';

let tsa: LocalTsa;
beforeAll(() => { tsa = startLocalTsa(); }, 60_000);
afterAll(() => { tsa.cleanup(); });

let dir: string; let ext: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'prove-'));
  ext = mkdtempSync(join(tmpdir(), 'prove-ext-'));
});
afterEach(() => { for (const d of [dir, ext]) rmSync(d, { recursive: true, force: true }); });

async function seed(n = 20, interval = 10): Promise<void> {
  const rec = Recorder.open(dir, {
    checkpointInterval: interval, fsync: false, anchor: { ...tsa.anchorOptions },
    signingKeyPath: join(ext, 'signing.key'), submitToWitness: false,
  });
  for (let i = 0; i < n; i++) {
    await rec.record({
      actor: { human: 'alice', agent_id: 'spiffe://x', tool: 'claude-code' },
      kind: i === 12 ? 'flag' : 'tool_call', target: `op_${i}`,
      args_digest: null, payload_ref: null,
      outcome: i === 12 ? 'flagged: credential access' : 'ok', duration_ms: 3,
    });
  }
  await rec.end();
}

/** Every file under a directory, by content. */
function snapshot(d: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (p: string, pre: string): void => {
    for (const e of readdirSync(p, { withFileTypes: true })) {
      const full = join(p, e.name); const rel = pre ? `${pre}/${e.name}` : e.name;
      if (e.isDirectory()) walk(full, rel);
      else out[rel] = readFileSync(full).toString('base64');
    }
  };
  walk(d, '');
  return out;
}

describe('SAFETY: the user’s own log is never touched', () => {
  it('leaves the source byte-identical', async () => {
    await seed();
    const before = snapshot(dir);
    const r = prove(dir, { tsaCaFile: tsa.caFile });
    expect(snapshot(dir)).toEqual(before);
    expect(r.sourceUntouched).toBe(true);
  });

  it('leaves no temp workspaces behind', async () => {
    await seed();
    const tmpBefore = readdirSync(tmpdir()).filter((f) => f.startsWith('orisan-prove-')).length;
    prove(dir, { tsaCaFile: tsa.caFile });
    const tmpAfter = readdirSync(tmpdir()).filter((f) => f.startsWith('orisan-prove-')).length;
    expect(tmpAfter).toBe(tmpBefore);
  });

  it('does not change the source even when the log is mid-session', async () => {
    const rec = Recorder.open(dir, {
      fsync: false, anchor: { enabled: false }, signingKeyPath: join(ext, 'signing.key'), submitToWitness: false,
    });
    for (let i = 0; i < 5; i++) {
      await rec.record({
        actor: { human: 'a', agent_id: 'spiffe://x', tool: 't' }, kind: 'tool_call',
        target: `op${i}`, args_digest: null, payload_ref: null, outcome: 'ok', duration_ms: 1,
      });
    }
    const size = statSync(join(dir, 'events-0000.jsonl')).size;
    prove(dir, {});
    expect(statSync(join(dir, 'events-0000.jsonl')).size).toBe(size);
    rec.close();
  });
});

describe('the edit attack is always caught', () => {
  it('detects an edited action, with no witness needed', async () => {
    await seed();
    const r = prove(dir, { tsaCaFile: tsa.caFile });
    const edit = r.runs.find((x) => x.attack === 'edit')!;
    expect(edit.detected).toBe(true);
    expect(edit.steps.at(-1)!.codes.some((c) => c.startsWith('chain_') || c.startsWith('checkpoint_'))).toBe(true);
    expect(edit.verdict).toMatch(/Caught/);
  });
});

describe('the delete attack tells the truth either way', () => {
  it('without a witness it reports NOT caught, and explains why', async () => {
    await seed();
    const r = prove(dir, { tsaCaFile: tsa.caFile });
    const del = r.runs.find((x) => x.attack === 'delete_tail')!;
    expect(del.detected).toBe(false);
    // The honest wording matters more than the result here.
    expect(del.verdict).toMatch(/honest answer/);
    expect(del.verdict).toMatch(/grey banner/);
    expect(del.verdict).toMatch(/Set up a witness/);
  });

  it('shows that a simple consistency check is fooled', async () => {
    await seed();
    const del = prove(dir, { tsaCaFile: tsa.caFile }).runs.find((x) => x.attack === 'delete_tail')!;
    const naive = del.steps.find((s) => s.title.includes('simple check'))!;
    expect(naive.detected).toBe(false);
    expect(naive.result).toMatch(/Nothing wrong/);
  });

  it('with a witness it reports caught', async () => {
    await seed();
    // A witness head that remembers a checkpoint the tampered copy will not have.
    const witnessFor = () => ({
      tsaCaFile: tsa.caFile,
      witnessService: {
        logId: 'a1111111-0000-4000-8000-000000000001',
        url: 'https://witness.test.invalid',
        reachable: true,
        signatureValid: true,
        head: {
          log_id: 'a1111111-0000-4000-8000-000000000001',
          latest_index: 1, latest_seq_to: 19,
          merkle_root: 'f'.repeat(64),
          witnessed_at: new Date().toISOString(),
          conflict: false, conflict_count: 0,
        },
      },
    });
    const r = prove(dir, { ...witnessFor(), witnessFor });
    const del = r.runs.find((x) => x.attack === 'delete_tail')!;
    expect(del.detected).toBe(true);
    expect(del.verdict).toMatch(/witness still remembers/);
  });
});

describe('degenerate logs do not produce nonsense', () => {
  it('an empty log says what to do instead of failing', () => {
    const r = prove(dir, {});
    expect(r.events).toBe(0);
    expect(r.runs).toHaveLength(2);
    expect(r.runs[0]!.steps[0]!.result).toMatch(/no actions yet/);
    expect(r.runs[1]!.verdict).toMatch(/Make a summary first/);
  });

  it('a log with events but no summaries explains the gap', async () => {
    const rec = Recorder.open(dir, {
      fsync: false, anchor: { enabled: false }, signingKeyPath: join(ext, 'signing.key'),
      submitToWitness: false, checkpointInterval: 1_000_000,
    });
    for (let i = 0; i < 3; i++) {
      await rec.record({
        actor: { human: 'a', agent_id: 'spiffe://x', tool: 't' }, kind: 'tool_call',
        target: `op${i}`, args_digest: null, payload_ref: null, outcome: 'ok', duration_ms: 1,
      });
    }
    rec.close();
    const del = prove(dir, {}).runs.find((x) => x.attack === 'delete_tail')!;
    expect(del.verdict).toMatch(/Make a summary first/);
  });
});

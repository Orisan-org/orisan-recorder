import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { DEMO_EVENT_COUNT, generateDemoSession } from '../src/demo.js';
import { EventIndex } from '../src/index-db.js';
import { EventStore } from '../src/store.js';

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'orisan-demo-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

describe('demo session', () => {
  it('ACCEPTANCE: writes 40 events with model calls, tool calls and one flag', () => {
    const r = generateDemoSession(dir);
    expect(r.events).toBe(DEMO_EVENT_COUNT);
    expect(r.flagged).toBe(1);

    const { store } = EventStore.open(dir);
    const events = store.readAll();
    expect(events).toHaveLength(40);

    const kinds = new Set(events.map((e) => e.kind));
    expect(kinds.has('model_call')).toBe(true);
    expect(kinds.has('tool_call')).toBe(true);
    expect(events.filter((e) => e.kind === 'flag')).toHaveLength(1);
  });

  it('produces a genuinely valid chain, not fabricated JSONL', () => {
    generateDemoSession(dir);
    expect(EventStore.open(dir).store.verifyChainOnly()).toEqual([]);
  });

  it('leaves the index populated so the UI has data immediately', () => {
    generateDemoSession(dir);
    const index = EventIndex.open(dir);
    expect(index.count()).toBe(40);
    expect(index.query({ kind: 'flag' })).toHaveLength(1);
    index.close();
  });

  it('is deterministic for a given seed and differs across seeds', () => {
    const a = generateDemoSession(dir, { seed: 1 });
    const other = mkdtempSync(join(tmpdir(), 'orisan-demo-'));
    try {
      const b = generateDemoSession(other, { seed: 1 });
      // Same seed: identical targets and timings (event_id/ts aside, which are
      // driven by the seeded clock, so hashes match too).
      const ta = EventStore.open(dir).store.readAll().map((e) => `${e.kind}:${e.target}:${e.ts}`);
      const tb = EventStore.open(other).store.readAll().map((e) => `${e.kind}:${e.target}:${e.ts}`);
      expect(ta).toEqual(tb);
      expect(a.events).toBe(b.events);

      const third = mkdtempSync(join(tmpdir(), 'orisan-demo-'));
      try {
        generateDemoSession(third, { seed: 2 });
        const tc = EventStore.open(third).store.readAll().map((e) => `${e.kind}:${e.target}:${e.ts}`);
        expect(tc).not.toEqual(ta);
      } finally { rmSync(third, { recursive: true, force: true }); }
    } finally { rmSync(other, { recursive: true, force: true }); }
  });

  it('contains no real-looking credentials or addresses', () => {
    generateDemoSession(dir);
    const raw = EventStore.open(dir).store.readAll().map((e) => JSON.stringify(e)).join('\n');
    expect(raw).not.toMatch(/@(gmail|outlook|yahoo)\.com/);
    expect(raw).not.toMatch(/\bsk-[A-Za-z0-9]{16,}/);
    expect(raw).toMatch(/example\.invalid/);
  });
});

describe('cli', () => {
  const tsx = join(process.cwd(), 'node_modules', '.bin', 'tsx');
  const cli = join(process.cwd(), 'src', 'cli.ts');

  function run(args: string[]): { code: number; out: string; err: string } {
    try {
      const out = execFileSync(tsx, [cli, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      return { code: 0, out, err: '' };
    } catch (e) {
      const err = e as { status?: number; stdout?: string; stderr?: string };
      return { code: err.status ?? -1, out: err.stdout ?? '', err: err.stderr ?? '' };
    }
  }

  it('demo then chain reports intact, exit 0', () => {
    expect(run(['demo', dir]).code).toBe(0);
    const r = run(['chain', dir]);
    expect(r.code).toBe(0);
    expect(r.out).toMatch(/chain intact: 40 events/);
  });

  it('chain output refuses to imply it detected a recompute', () => {
    run(['demo', dir]);
    expect(run(['chain', dir]).out).toMatch(/cannot detect a chain recomputed/);
  });

  it('ACCEPTANCE: verify is absent and exits 2 (cannot-verify), never 0', () => {
    run(['demo', dir]);
    const r = run(['verify', dir]);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/not implemented yet \(R1\.4\)/);
    expect(r.err).not.toMatch(/\bverified\b/i);
  });
});

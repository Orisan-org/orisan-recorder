import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { EventIndex } from '../src/index-db.js';
import { EventStore, peekHeadSeq } from '../src/store.js';
import type { EventInput } from '../src/schema.js';

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'orisan-idx-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

function ev(i: number, over: Partial<EventInput> = {}): EventInput {
  return {
    actor: {
      human: i % 2 === 0 ? 'alice' : null,
      agent_id: i % 3 === 0 ? 'spiffe://orisan/agent/a' : 'spiffe://orisan/agent/b',
      tool: 'claude-code',
    },
    kind: i % 5 === 0 ? 'model_call' : 'tool_call',
    target: `tool.${i}`,
    args_digest: null,
    payload_ref: null,
    outcome: 'ok',
    duration_ms: i,
    ts: new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString(),
    ...over,
  };
}

function seeded(n: number) {
  const { store } = EventStore.open(dir, { fsync: false });
  for (let i = 0; i < n; i++) store.append(ev(i));
  const index = EventIndex.open(dir);
  index.rebuild(store);
  return { store, index };
}

describe('index as a cache', () => {
  it('rebuilds from the segments and matches the log exactly', () => {
    const { store, index } = seeded(120);
    expect(index.count()).toBe(store.count);
    expect(index.query({ limit: 1 })[0]!.seq).toBe(0);
    index.close();
  });

  it('is fully reconstructable after being deleted', () => {
    const { store, index } = seeded(50);
    index.close();
    rmSync(join(dir, 'index.sqlite'), { force: true });
    rmSync(join(dir, 'index.sqlite-wal'), { force: true });
    rmSync(join(dir, 'index.sqlite-shm'), { force: true });

    const fresh = EventIndex.open(dir);
    expect(fresh.count()).toBe(0);
    expect(fresh.rebuild(store)).toBe(50);
    expect(fresh.count()).toBe(50);
    fresh.close();
  });

  it('rebuild is idempotent and does not duplicate rows', () => {
    const { store, index } = seeded(30);
    index.rebuild(store);
    index.rebuild(store);
    expect(index.count()).toBe(30);
    index.close();
  });

  it('never stores chain fields — verification must read the segments', () => {
    const { index } = seeded(5);
    const row = index.query({ limit: 1 })[0]! as unknown as Record<string, unknown>;
    expect(row).not.toHaveProperty('hash');
    expect(row).not.toHaveProperty('prev_hash');
    index.close();
  });
});

describe('queries the UI needs', () => {
  it('filters by kind, agent and time window, ordered by seq', () => {
    const { index } = seeded(60);

    const models = index.query({ kind: 'model_call' });
    expect(models.length).toBe(12);
    expect(models.every((r) => r.kind === 'model_call')).toBe(true);
    expect(models.map((r) => r.seq)).toEqual([...models.map((r) => r.seq)].sort((a, b) => a - b));

    const agentA = index.query({ agentId: 'spiffe://orisan/agent/a' });
    expect(agentA.length).toBe(20);

    const window = index.query({
      since: new Date(Date.UTC(2026, 0, 1, 0, 0, 10)).toISOString(),
      until: new Date(Date.UTC(2026, 0, 1, 0, 0, 19)).toISOString(),
    });
    expect(window.map((r) => r.seq)).toEqual([...Array(10).keys()].map((i) => i + 10));

    index.close();
  });

  it('paginates', () => {
    const { index } = seeded(25);
    expect(index.query({ limit: 10 }).map((r) => r.seq)).toEqual([...Array(10).keys()]);
    expect(index.query({ limit: 10, offset: 20 }).map((r) => r.seq)).toEqual([20, 21, 22, 23, 24]);
    index.close();
  });

  it('summarises by kind', () => {
    const { index } = seeded(50);
    const byKind = index.countByKind();
    expect(byKind['model_call']! + byKind['tool_call']!).toBe(50);
    index.close();
  });
});

describe('sessions come from the index, and staleness is cheap to spot', () => {
  it('groups by session with counts, agents and seq range', () => {
    const { store, index } = seeded(0);
    store.close();
    const a = EventStore.open(dir, { fsync: false, sessionId: '11111111-0000-4000-8000-000000000001' }).store;
    for (let i = 0; i < 4; i++) a.append(ev(i));
    a.close();
    const b = EventStore.open(dir, { fsync: false, sessionId: '22222222-0000-4000-8000-000000000002' }).store;
    for (let i = 0; i < 6; i++) b.append(ev(i, { kind: i === 2 ? 'flag' : 'tool_call' }));
    b.close();

    index.rebuild(EventStore.open(dir, { readOnly: true }).store);
    const rows = index.sessions();
    expect(rows).toHaveLength(2);
    const second = rows.find((r) => r.session_id.startsWith('22222222'))!;
    expect(second.events).toBe(6);
    expect(second.flagged).toBe(1);
    expect(second.first_seq).toBe(4);
    expect(second.last_seq).toBe(9);
    index.close();
  });

  it('maxSeq matches the log head, and diverges when the index falls behind', () => {
    const { store, index } = seeded(10);
    expect(index.maxSeq()).toBe(peekHeadSeq(dir));

    store.append(ev(99));
    store.close();
    // Index untouched: the probe must notice without reading the log.
    expect(index.maxSeq()).not.toBe(peekHeadSeq(dir));

    index.rebuild(EventStore.open(dir, { readOnly: true }).store);
    expect(index.maxSeq()).toBe(peekHeadSeq(dir));
    index.close();
  });

  it('peekHeadSeq is -1 for an empty log', () => {
    expect(peekHeadSeq(mkdtempSync(join(tmpdir(), 'empty-')))).toBe(-1);
  });
});

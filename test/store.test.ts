import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawn } from 'node:child_process';
import { appendFileSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { EventStore, listSegments, segmentName } from '../src/store.js';
import { GENESIS_PREV_HASH, type EventInput } from '../src/schema.js';

/** Resolve the tsx binary directly; going through `npx` adds a process layer
 * that does not forward signals. */
function tsxBin(): string {
  return join(process.cwd(), 'node_modules', '.bin', 'tsx');
}

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'orisan-rec-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function ev(i: number): EventInput {
  return {
    actor: { human: 'alice', agent_id: 'spiffe://orisan/agent/test', tool: 'claude-code' },
    kind: i % 7 === 0 ? 'model_call' : 'tool_call',
    target: `tool.${i}`,
    args_digest: null,
    payload_ref: null,
    outcome: 'ok',
    duration_ms: i,
  };
}

describe('append and read back', () => {
  it('ACCEPTANCE: appends 1000 events and the chain verifies clean', () => {
    const { store } = EventStore.open(dir, { maxEventsPerSegment: 400 });
    for (let i = 0; i < 1000; i++) store.append(ev(i));
    store.close();

    const { store: reopened } = EventStore.open(dir);
    expect(reopened.count).toBe(1000);
    expect(reopened.verifyChainOnly()).toEqual([]);

    const events = reopened.readAll();
    expect(events).toHaveLength(1000);
    expect(events[0]!.seq).toBe(0);
    expect(events[0]!.prev_hash).toBe(GENESIS_PREV_HASH);
    expect(events[999]!.seq).toBe(999);
  });

  it('rolls segments and keeps seq monotonic across them', () => {
    const { store } = EventStore.open(dir, { maxEventsPerSegment: 100 });
    for (let i = 0; i < 250; i++) store.append(ev(i));
    store.close();

    expect(listSegments(dir)).toEqual([segmentName(0), segmentName(1), segmentName(2)]);
    const seqs = EventStore.open(dir, { readOnly: true }).store.readAll().map((e) => e.seq);
    expect(seqs).toEqual([...Array(250).keys()]);
  });

  it('resumes the chain across a clean close and reopen', () => {
    const first = EventStore.open(dir).store;
    for (let i = 0; i < 10; i++) first.append(ev(i));
    const headHash = first.head.hash;
    first.close();

    const second = EventStore.open(dir).store;
    const next = second.append(ev(10));
    expect(next.seq).toBe(10);
    expect(next.prev_hash).toBe(headHash);
    expect(second.verifyChainOnly()).toEqual([]);
  });
});

describe('tamper detection at the store level', () => {
  it('ACCEPTANCE: flipping one byte in an old event is caught and names the seq', () => {
    const { store } = EventStore.open(dir, { maxEventsPerSegment: 1000 });
    for (let i = 0; i < 100; i++) store.append(ev(i));
    store.close();

    // Edit event 42 in place, leaving its hash untouched — the careless attack.
    const path = join(dir, segmentName(0));
    const lines = readFileSync(path, 'utf8').split('\n').filter(Boolean);
    const target = JSON.parse(lines[42]!) as Record<string, unknown>;
    expect(target['seq']).toBe(42);
    target['outcome'] = 'error';
    lines[42] = JSON.stringify(target);
    writeFileSync(path, `${lines.join('\n')}\n`);

    const breaks = EventStore.open(dir, { readOnly: true }).store.verifyChainOnly();
    expect(breaks).toHaveLength(1);
    expect(breaks[0]!.seq).toBe(42);
    expect(breaks[0]!.reason).toBe('hash_mismatch');
  });
});

describe('crash safety', () => {
  it('truncates and reports a torn trailing line, leaving the chain intact', () => {
    const { store } = EventStore.open(dir, { maxEventsPerSegment: 1000 });
    for (let i = 0; i < 20; i++) store.append(ev(i));
    store.close();

    // Simulate a write that died halfway through the final line.
    const path = join(dir, segmentName(0));
    const before = statSync(path).size;
    const torn = '{"v":1,"seq":20,"event_id":"partial';
    appendFileSync(path, torn);
    expect(statSync(path).size).toBe(before + torn.length);

    const { store: recovered, recovery } = EventStore.open(dir);
    expect(recovery.truncatedPartialTail).toBe(true);
    expect(recovery.bytesDiscarded).toBe(torn.length);
    expect(recovery.segment).toBe(segmentName(0));
    expect(statSync(path).size).toBe(before);
    expect(recovered.count).toBe(20);
    expect(recovered.verifyChainOnly()).toEqual([]);

    // And the store keeps going from the right place.
    const next = recovered.append(ev(20));
    expect(next.seq).toBe(20);
    expect(recovered.verifyChainOnly()).toEqual([]);
  });

  it('refuses a torn line in the middle of the chain rather than dropping a record', () => {
    const { store } = EventStore.open(dir, { maxEventsPerSegment: 10 });
    for (let i = 0; i < 25; i++) store.append(ev(i));
    store.close();
    // Corrupt an earlier segment's tail; that cannot be a crash artefact.
    appendFileSync(join(dir, segmentName(0)), '{"v":1,"seq":');
    expect(() => EventStore.open(dir)).toThrow(/corrupt segment/);
  });

  it('ACCEPTANCE: kill -9 mid-write, restart, no corruption and at most the last line lost', async () => {
    // detached:true makes the child a process-group leader so we can signal the
    // whole group. Without it, `npx` forwards nothing and the real writer (a
    // grandchild) survives the kill and keeps appending underneath the
    // recovery — which silently turns this into a test of nothing.
    const child = spawn(tsxBin(), ['test/fixtures/appender.ts', dir], {
      cwd: process.cwd(),
      stdio: 'ignore',
      detached: true,
    });

    // Wait until the appender is genuinely writing.
    const path = join(dir, segmentName(0));
    const deadline = Date.now() + 20_000;
    for (;;) {
      let size = 0;
      try { size = statSync(path).size; } catch { /* not created yet */ }
      if (size > 50_000) break;
      if (Date.now() > deadline) { child.kill('SIGKILL'); throw new Error('appender never produced output'); }
      await new Promise((r) => setTimeout(r, 50));
    }

    process.kill(-child.pid!, 'SIGKILL');
    await new Promise<void>((resolve) => child.on('exit', () => resolve()));

    // Prove the writer is actually gone: the segment must stop growing.
    const settled = async () => {
      let last = -1;
      for (let i = 0; i < 40; i++) {
        const size = statSync(path).size;
        if (size === last) return true;
        last = size;
        await new Promise((r) => setTimeout(r, 50));
      }
      return false;
    };
    expect(await settled()).toBe(true);

    const { store, recovery } = EventStore.open(dir);
    const events = store.readAll();

    expect(events.length).toBeGreaterThan(0);
    // No corruption: every surviving record chains correctly.
    expect(store.verifyChainOnly()).toEqual([]);
    // Contiguous from genesis — nothing lost from the middle.
    expect(events.map((e) => e.seq)).toEqual([...Array(events.length).keys()]);
    // If anything was lost it was the tail, and it was reported.
    if (recovery.truncatedPartialTail) {
      expect(recovery.bytesDiscarded).toBeGreaterThan(0);
      expect(recovery.segment).toBe(segmentName(0));
    }
    // The store is usable again.
    const resumed = store.append(ev(999));
    expect(resumed.seq).toBe(events.length);
    expect(store.verifyChainOnly()).toEqual([]);
  });
});

describe('v3: the store owns the session id', () => {
  it('stamps every append with one session, defaulting to a fresh uuid', () => {
    const { store } = EventStore.open(dir, { fsync: false });
    for (let i = 0; i < 5; i++) store.append(ev(i));
    store.close();

    const events = EventStore.open(dir, { readOnly: true }).store.readAll();
    const sessions = new Set(events.map((e) => e.session_id));
    expect(sessions.size).toBe(1);
    expect([...sessions][0]).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('a second store over the same log is a second session', () => {
    const a = EventStore.open(dir, { fsync: false }).store;
    a.append(ev(0));
    const first = a.session;
    a.close();

    const b = EventStore.open(dir, { fsync: false }).store;
    b.append(ev(1));
    expect(b.session).not.toBe(first);
    b.close();

    const events = EventStore.open(dir, { readOnly: true }).store.readAll();
    expect(new Set(events.map((e) => e.session_id)).size).toBe(2);
    // Two sessions, one chain: the log is still contiguous.
    expect(EventStore.open(dir, { readOnly: true }).store.verifyChainOnly()).toEqual([]);
  });

  it('an explicit session id is honoured', () => {
    const id = '7a1f0000-0000-4000-8000-00000000abcd';
    const { store } = EventStore.open(dir, { fsync: false, sessionId: id });
    store.append(ev(0));
    store.close();
    expect(EventStore.open(dir, { readOnly: true }).store.readAll()[0]!.session_id).toBe(id);
  });
});

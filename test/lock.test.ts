/**
 * Issue #1 — two recorders on one log directory.
 *
 * THIS TEST STAYS IN CI PERMANENTLY. It is the regression guard for a bug that
 * destroyed data silently and could not be repaired afterwards: two processes
 * appending 30 events each produced 60 lines carrying 30 distinct sequence
 * numbers, every one duplicated with a different prev_hash.
 *
 * The writers are real child processes. Two `EventStore` instances inside one
 * test process share nothing that matters, so an in-process version of this
 * would pass while the actual failure stayed open.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { EventStore } from '../src/store.js';
import type { EventInput } from '../src/schema.js';
import {
  LOCK_FILENAME, LogDirectoryLockedError, acquireWriterLock, currentLockHolder, pidIsAlive,
} from '../src/lock.js';

const TSX = join(process.cwd(), 'node_modules', '.bin', 'tsx');
const WRITER = join(process.cwd(), 'test', 'fixtures', 'concurrent-writer.ts');

interface Ran { code: number | null; lines: Record<string, any>[] }

function runWriter(dir: string, tag: string, count: number, holdMs = 0): Promise<Ran> {
  return new Promise((resolve) => {
    const p = spawn(TSX, [WRITER, dir, tag, String(count), String(holdMs)], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    p.stdout.on('data', (d: Buffer) => { out += d.toString(); });
    p.stderr.on('data', () => { /* tsx noise */ });
    p.on('exit', (code) => {
      resolve({
        code,
        lines: out.split('\n').filter(Boolean).flatMap((l) => { try { return [JSON.parse(l)]; } catch { return []; } }),
      });
    });
  });
}

/** A minimal valid event. The schema rejects unknown fields, deliberately. */
const ev = (target: string): EventInput => ({
  actor: { human: 'tester', agent_id: 'a', tool: 'vitest' },
  kind: 'tool_call',
  target,
  args_digest: null,
  payload_ref: null,
  outcome: 'ok',
  duration_ms: null,
});

const eventsOnDisk = (dir: string): Record<string, any>[] =>
  readdirSync(dir).filter((f) => /^events-\d{4}\.jsonl$/.test(f)).sort()
    .flatMap((f) => readFileSync(join(dir, f), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)));

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'orisan-lock-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

describe('two recorders on one directory (the regression)', () => {
  it('the second refuses, and the chain stays intact', async () => {
    // A holds the lock across a pause so B is guaranteed to arrive while it is live.
    const a = runWriter(dir, 'A', 30, 900);
    await new Promise((r) => setTimeout(r, 400));
    const b = await runWriter(dir, 'B', 30);
    const first = await a;

    expect(first.code, JSON.stringify(first.lines)).toBe(0);
    expect(first.lines[0]!['result']).toBe('wrote');

    expect(b.code, JSON.stringify(b.lines)).toBe(3);
    expect(b.lines[0]!['result']).toBe('refused');
    expect(b.lines[0]!['reason']).toBe('held');

    const events = eventsOnDisk(dir);
    const seqs = events.map((e) => e.seq as number);
    expect(events).toHaveLength(30);
    expect(new Set(seqs).size).toBe(30);
    expect(seqs).toEqual([...Array(30).keys()]);

    // And the chain still links, which is what the duplicates destroyed.
    expect(EventStore.open(dir, { readOnly: true }).store.verifyChainOnly()).toEqual([]);
  }, 60_000);

  it('names the holder rather than failing vaguely', async () => {
    const a = runWriter(dir, 'A', 5, 900);
    await new Promise((r) => setTimeout(r, 400));
    const b = await runWriter(dir, 'B', 5);
    await a;

    const msg = String(b.lines[0]!['message']);
    expect(b.lines[0]!['holderPid']).toBeGreaterThan(0);
    expect(msg).toContain('is being recorded to by pid');
    expect(msg).toContain('corrupt the chain');
    expect(msg).toMatch(/record to a different directory/);
  }, 60_000);

  it('the second writer can start once the first has finished', async () => {
    expect((await runWriter(dir, 'A', 10)).code).toBe(0);
    const b = await runWriter(dir, 'B', 10);
    expect(b.code, JSON.stringify(b.lines)).toBe(0);
    const seqs = eventsOnDisk(dir).map((e) => e.seq as number);
    expect(seqs).toEqual([...Array(20).keys()]);
    expect(EventStore.open(dir, { readOnly: true }).store.verifyChainOnly()).toEqual([]);
  }, 60_000);

  it('leaves no lock file behind after a clean exit', async () => {
    await runWriter(dir, 'A', 5);
    expect(existsSync(join(dir, LOCK_FILENAME))).toBe(false);
    expect(currentLockHolder(dir)).toBeNull();
  }, 60_000);

  it('reclaims the lock of a recorder that was killed', async () => {
    // SIGKILL cannot run an exit handler, so this is the real stale case.
    //
    // `detached` and a kill of the whole GROUP, not of `p`. The tsx shim execs
    // a child node process, so signalling the shim leaves the grandchild
    // running — and still legitimately holding the lock. The first version of
    // this test did exactly that and "failed", when the refusal was correct.
    const p = spawn(TSX, [WRITER, dir, 'A', '5', '5000'], { stdio: ['ignore', 'pipe', 'pipe'], detached: true });
    await new Promise((r) => setTimeout(r, 1500));
    expect(existsSync(join(dir, LOCK_FILENAME))).toBe(true);
    const holder = currentLockHolder(dir)!.pid;
    process.kill(-p.pid!, 'SIGKILL');
    await new Promise((r) => p.on('exit', r));
    await new Promise((r) => setTimeout(r, 200));
    expect(pidIsAlive(holder), 'the recorder must actually be dead for this to test anything').toBe(false);
    expect(existsSync(join(dir, LOCK_FILENAME))).toBe(true); // outlived its holder

    const b = await runWriter(dir, 'B', 5);
    expect(b.code, JSON.stringify(b.lines)).toBe(0);
    expect(EventStore.open(dir, { readOnly: true }).store.verifyChainOnly()).toEqual([]);
  }, 60_000);
});

describe('the lock does not get in the way of reading', () => {
  it('a read-only open works while a writer holds the lock', () => {
    const { store } = EventStore.open(dir, { fsync: false });
    try {
      store.append(ev('t'));
      const reader = EventStore.open(dir, { readOnly: true }).store;
      expect(reader.count).toBe(1);
      expect(reader.verifyChainOnly()).toEqual([]);
    } finally { store.close(); }
  });

  it('a read-only open takes no lock of its own', () => {
    EventStore.open(dir, { readOnly: true });
    expect(existsSync(join(dir, LOCK_FILENAME))).toBe(false);
  });
});

describe('the lock file itself', () => {
  it('records pid, hostname and a start time', () => {
    const lock = acquireWriterLock(dir);
    try {
      const info = currentLockHolder(dir)!;
      expect(info.pid).toBe(process.pid);
      expect(info.hostname).toBe(hostname());
      expect(new Date(info.started_at).getTime()).toBeGreaterThan(0);
    } finally { lock.release(); }
  });

  it('release is idempotent', () => {
    const lock = acquireWriterLock(dir);
    lock.release();
    lock.release();
    expect(existsSync(join(dir, LOCK_FILENAME))).toBe(false);
  });

  it('refuses a lock held by a live process on this host', () => {
    const lock = acquireWriterLock(dir);
    try {
      expect(() => acquireWriterLock(dir, { pid: process.pid + 100000 }))
        .toThrow(LogDirectoryLockedError);
    } finally { lock.release(); }
  });

  it('reclaims a lock naming a dead pid on this host', () => {
    // A pid that has certainly exited: our own child, awaited.
    const dead = 999_999;
    expect(pidIsAlive(dead)).toBe(false);
    writeFileSync(join(dir, LOCK_FILENAME),
      JSON.stringify({ pid: dead, hostname: hostname(), started_at: new Date().toISOString() }));
    const lock = acquireWriterLock(dir);
    try { expect(currentLockHolder(dir)!.pid).toBe(process.pid); }
    finally { lock.release(); }
  });

  it('refuses a lock from another host, because liveness cannot be checked there', () => {
    writeFileSync(join(dir, LOCK_FILENAME),
      JSON.stringify({ pid: 999_999, hostname: 'some-other-box', started_at: new Date().toISOString() }));
    try {
      acquireWriterLock(dir);
      expect.unreachable('should have refused');
    } catch (e) {
      expect(e).toBeInstanceOf(LogDirectoryLockedError);
      expect((e as LogDirectoryLockedError).reason).toBe('foreign_host');
      expect((e as LogDirectoryLockedError).message).toContain('some-other-box');
    }
  });

  it('refuses an unreadable lock file rather than assuming it is stale', () => {
    writeFileSync(join(dir, LOCK_FILENAME), 'not json at all');
    try {
      acquireWriterLock(dir);
      expect.unreachable('should have refused');
    } catch (e) {
      expect((e as LogDirectoryLockedError).reason).toBe('unreadable');
    }
  });

  it('tells a developer who reopened the same directory in one process', () => {
    const lock = acquireWriterLock(dir);
    try {
      expect(() => EventStore.open(dir)).toThrow(/already open for writing by this process/);
    } finally { lock.release(); }
  });

  it('does not delete a lock that was reclaimed by someone else', () => {
    const lock = acquireWriterLock(dir);
    // Simulate: we went stale, another recorder took over.
    writeFileSync(join(dir, LOCK_FILENAME),
      JSON.stringify({ pid: process.pid + 1, hostname: hostname(), started_at: new Date().toISOString() }));
    lock.release();
    expect(existsSync(join(dir, LOCK_FILENAME))).toBe(true);
    expect(currentLockHolder(dir)!.pid).toBe(process.pid + 1);
  });
});

describe('nextSeq and lastHash come from disk, not from memory alone', () => {
  it('a reopened store continues the chain from what is on disk', () => {
    const first = EventStore.open(dir, { fsync: false }).store;
    for (let i = 0; i < 5; i++) {
      first.append(ev(`t-${i}`));
    }
    const head = first.head;
    first.close();

    const second = EventStore.open(dir, { fsync: false }).store;
    try {
      expect(second.count).toBe(5);
      expect(second.head).toEqual(head);
      second.append(ev('t'));
      expect(second.verifyChainOnly()).toEqual([]);
    } finally { second.close(); }
  });

  it('refuses to append when the segment grew behind its back', () => {
    // The lock should make this impossible. It is checked anyway, because a
    // forked chain cannot be repaired and one fstat is cheap.
    const store = EventStore.open(dir, { fsync: false }).store;
    try {
      store.append(ev('t'));
      const seg = join(dir, readdirSync(dir).find((f) => f.endsWith('.jsonl'))!);
      writeFileSync(seg, `${readFileSync(seg, 'utf8')}{"smuggled":true}\n`);
      expect(() => store.append(ev('t')))
        .toThrow(/changed underneath this recorder/);
    } finally { store.close(); }
  });
});

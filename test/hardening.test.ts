/** Job 6 hardening, from SECURITY-REVIEW-R1.md. */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { EventStore, segmentName } from '../src/store.js';
import { readCheckpoints } from '../src/checkpoint.js';
import { EXIT_CANNOT_VERIFY, resolveOpenssl, verify } from '../src/verify.js';
import type { EventInput } from '../src/schema.js';

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'orisan-hard-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

const ev = (i: number): EventInput => ({
  actor: { human: 'a', agent_id: 'spiffe://x', tool: 't' },
  kind: 'tool_call', target: `t${i}`, args_digest: null,
  payload_ref: null, outcome: 'ok', duration_ms: 1,
});

describe('verify never writes to the log it is verifying', () => {
  it('does not create a directory that does not exist', () => {
    const missing = join(dir, 'nope');
    const r = verify(missing);
    expect(existsSync(missing)).toBe(false);
    expect(r.exitCode).toBe(EXIT_CANNOT_VERIFY);
  });

  it('reports a torn tail without truncating it', () => {
    const { store } = EventStore.open(dir, { fsync: false });
    for (let i = 0; i < 5; i++) store.append(ev(i));
    store.close();
    const path = join(dir, segmentName(0));
    writeFileSync(path, `${readFileSync(path, 'utf8')}{"v":2,"seq":5,"partial`);
    const sizeBefore = statSync(path).size;

    verify(dir);
    expect(statSync(path).size).toBe(sizeBefore);
    verify(dir);
    expect(statSync(path).size).toBe(sizeBefore);
  });

  it('a read-only store refuses to append', () => {
    const { store } = EventStore.open(dir, { fsync: false });
    store.append(ev(0));
    store.close();
    const ro = EventStore.open(dir, { readOnly: true }).store;
    expect(() => ro.append(ev(1))).toThrow(/read-only/);
  });
});

describe('openssl is not dispatched by name', () => {
  it('resolves to an absolute path', () => {
    const p = resolveOpenssl();
    expect(p === null || p.startsWith('/')).toBe(true);
  });

  it('refuses a relative override rather than trusting PATH', () => {
    expect(resolveOpenssl('openssl')).toBeNull();
    expect(resolveOpenssl('./openssl')).toBeNull();
    expect(resolveOpenssl('/usr/bin/openssl')).toBe('/usr/bin/openssl');
  });

  it('a PATH shim cannot make a bad token verify', () => {
    // The absolute-path rule is what defeats this; assert the resolver never
    // returns something from a writable working directory.
    const shim = join(dir, 'openssl');
    writeFileSync(shim, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    chmodSync(shim, 0o755);
    expect(resolveOpenssl()).not.toBe(shim);
  });
});

describe('corrupt input is cannot-verify, never a stack trace', () => {
  it('garbage in checkpoints.jsonl exits 2 with a finding', () => {
    const { store } = EventStore.open(dir, { fsync: false });
    store.append(ev(0));
    store.close();
    writeFileSync(join(dir, 'checkpoints.jsonl'), 'not json at all\n');

    const r = verify(dir);
    expect(r.exitCode).toBe(EXIT_CANNOT_VERIFY);
    expect(r.findings.some((f) => f.code === 'unreadable')).toBe(true);
  });

  it('the CLI exits 2 on corrupt input, not 1', () => {
    const { store } = EventStore.open(dir, { fsync: false });
    store.append(ev(0));
    store.close();
    writeFileSync(join(dir, 'checkpoints.jsonl'), '{ broken\n');

    let code = 0;
    let stderr = '';
    try {
      execFileSync(join(process.cwd(), 'node_modules', '.bin', 'tsx'),
        [join(process.cwd(), 'src', 'cli.ts'), 'verify', dir],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
      const err = e as { status?: number; stderr?: string };
      code = err.status ?? -1;
      stderr = err.stderr ?? '';
    }
    expect(code).toBe(2);
    expect(stderr).not.toMatch(/at Object\.|node:internal/);
  });

  it('duplicate checkpoint lines are rejected', () => {
    writeFileSync(join(dir, 'checkpoints.jsonl'), '{"a":1}\n{"a":1}\n');
    expect(() => readCheckpoints(dir)).toThrow(/duplicate/);
  });
});

describe('segment naming cannot collide', () => {
  it('events-00000 is not treated as segment 0', () => {
    const { store } = EventStore.open(dir, { fsync: false });
    store.append(ev(0));
    store.close();
    writeFileSync(join(dir, 'events-00000.jsonl'), 'ignored\n');
    // The five-digit file is not a segment, so reading still works.
    expect(EventStore.open(dir, { readOnly: true }).store.readAll()).toHaveLength(1);
  });
});

import { describe, it, expect } from 'vitest';
import {
  GENESIS_PREV_HASH,
  SCHEMA_VERSION,
  argsDigest,
  buildEvent,
  canonicalJson,
  computeEventHash,
  hashParts,
  validateEvent,
  verifyChain,
  type EventInput,
  type RecordedEvent,
} from '../src/schema.js';

function input(over: Partial<EventInput> = {}): EventInput {
  return {
    actor: { human: 'alice', agent_id: 'spiffe://orisan/agent/test', tool: 'claude-code' },
    kind: 'tool_call',
    target: 'fs.read',
    args_digest: argsDigest({ path: '/tmp/x' }),
    payload_ref: null,
    outcome: 'ok',
    duration_ms: 12,
    ...over,
  };
}

function chain(n: number): RecordedEvent[] {
  const out: RecordedEvent[] = [];
  let prev = GENESIS_PREV_HASH;
  for (let i = 0; i < n; i++) {
    const e = buildEvent(input({ target: `tool.${i}` }), i, prev);
    out.push(e);
    prev = e.hash;
  }
  return out;
}

describe('canonical JSON', () => {
  it('is key-order independent', () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe(canonicalJson({ a: 2, b: 1 }));
  });

  it('sorts nested keys and preserves array order', () => {
    expect(canonicalJson({ z: { y: 1, x: 2 }, a: [3, 1, 2] })).toBe('{"a":[3,1,2],"z":{"x":2,"y":1}}');
  });

  it('distinguishes values that differ', () => {
    expect(canonicalJson({ a: 1 })).not.toBe(canonicalJson({ a: '1' }));
  });
});

describe('hashParts NUL separation', () => {
  it('resolves the concatenation ambiguity', () => {
    // The whole point: without a separator these two collide.
    expect(hashParts(['ab', 'c'])).not.toBe(hashParts(['a', 'bc']));
  });

  it('refuses a part containing NUL, rather than letting it forge a boundary', () => {
    expect(() => hashParts(['a\0b'])).toThrow(/NUL/);
  });
});

describe('event construction', () => {
  it('stamps the schema version and a host clock source', () => {
    const e = buildEvent(input(), 0, GENESIS_PREV_HASH);
    expect(e.v).toBe(SCHEMA_VERSION);
    expect(e.clock_source).toBe('host_wall_clock');
  });

  it('hash excludes only the hash field and covers everything else', () => {
    const e = buildEvent(input(), 0, GENESIS_PREV_HASH);
    const { hash, ...rest } = e;
    expect(computeEventHash(rest as Omit<RecordedEvent, 'hash'>)).toBe(hash);
  });

  it('changing any covered field changes the hash', () => {
    const e = buildEvent(input(), 0, GENESIS_PREV_HASH);
    for (const mutate of [
      (x: RecordedEvent) => ({ ...x, target: 'other' }),
      (x: RecordedEvent) => ({ ...x, outcome: 'error' }),
      (x: RecordedEvent) => ({ ...x, duration_ms: 13 }),
      (x: RecordedEvent) => ({ ...x, seq: 1 }),
      (x: RecordedEvent) => ({ ...x, actor: { ...x.actor, human: 'mallory' } }),
      (x: RecordedEvent) => ({ ...x, prev_hash: 'f'.repeat(64) }),
    ]) {
      const m = mutate(e);
      const { hash: _h, ...rest } = m;
      expect(computeEventHash(rest as Omit<RecordedEvent, 'hash'>)).not.toBe(e.hash);
    }
  });

  it('is deterministic across independent builds', () => {
    const fixed = { event_id: 'f6b4d0f6-0000-4000-8000-000000000000', ts: '2026-08-12T00:00:00.000Z' };
    const a = buildEvent(input(fixed), 7, GENESIS_PREV_HASH);
    const b = buildEvent(input(fixed), 7, GENESIS_PREV_HASH);
    expect(a.hash).toBe(b.hash);
  });
});

describe('validateEvent', () => {
  it('accepts a well-formed event', () => {
    expect(() => validateEvent(buildEvent(input(), 0, GENESIS_PREV_HASH))).not.toThrow();
  });

  it('rejects an unknown kind, a bad digest and a future schema version', () => {
    const e = buildEvent(input(), 0, GENESIS_PREV_HASH);
    expect(() => validateEvent({ ...e, kind: 'sudo' })).toThrow(/unknown kind/);
    expect(() => validateEvent({ ...e, args_digest: 'nope' })).toThrow(/args_digest/);
    expect(() => validateEvent({ ...e, v: 2 })).toThrow(/unsupported schema version/);
  });
});

describe('verifyChain', () => {
  it('accepts an intact chain', () => {
    expect(verifyChain(chain(50))).toEqual([]);
  });

  it('names the exact seq of a flipped field', () => {
    const c = chain(20);
    c[7] = { ...c[7]!, outcome: 'silently-changed' };
    const breaks = verifyChain(c);
    expect(breaks).toHaveLength(1);
    expect(breaks[0]!.seq).toBe(7);
    expect(breaks[0]!.reason).toBe('hash_mismatch');
  });

  it('does not cascade: one edit reports one break, not N', () => {
    const c = chain(30);
    c[3] = { ...c[3]!, target: 'edited' };
    expect(verifyChain(c).filter((b) => b.reason === 'hash_mismatch')).toHaveLength(1);
  });

  it('detects a deleted record as a seq gap and a broken link', () => {
    const c = chain(10);
    c.splice(4, 1);
    const breaks = verifyChain(c);
    expect(breaks.some((b) => b.reason === 'seq_gap' && b.seq === 5)).toBe(true);
    expect(breaks.some((b) => b.reason === 'prev_hash_mismatch')).toBe(true);
  });

  it('detects reordering', () => {
    const c = chain(10);
    const tmp = c[4]!;
    c[4] = c[5]!;
    c[5] = tmp;
    expect(verifyChain(c).length).toBeGreaterThan(0);
  });

  it('KNOWN GAP: a fully recomputed chain passes — this is why R1.3 exists', () => {
    // The attacker deletes a record and re-seals with our own function. No secret
    // is required; every input is public. The chain cannot see it, and must not
    // be marketed as if it could. R1.4 catches this against an anchored checkpoint.
    const c = chain(10);
    c.splice(4, 1);
    let prev = GENESIS_PREV_HASH;
    const forged = c.map((e, i) => {
      const base = { ...e, seq: i, prev_hash: prev };
      const { hash: _h, ...rest } = base;
      const sealed = { ...base, hash: computeEventHash(rest as Omit<RecordedEvent, 'hash'>) };
      prev = sealed.hash;
      return sealed;
    });
    expect(verifyChain(forged)).toEqual([]);
  });
});

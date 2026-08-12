/**
 * The two R1 acceptance tests that CANNOT pass yet, kept visible as skips.
 *
 * A missing test looks identical to a passing one on a summary line. These are
 * the two acceptance criteria that depend on R1.3 (signed, RFC 3161-anchored
 * checkpoints) and R1.4 (the verify command), and they are the two that matter
 * most — the first is the attack that defeated two shipping competitors. They
 * stay here, skipped and named, so nobody reads a green run as covering them.
 */

import { describe, it, expect } from 'vitest';
import { GENESIS_PREV_HASH, buildEvent, computeEventHash, verifyChain, type RecordedEvent } from '../src/schema.js';

describe('R1.4 acceptance — pending R1.3', () => {
  it.skip('THE KEY TEST: delete 3 events, recompute all hashes with our own hash function, verify exits 1 naming the checkpoint', () => {
    // Blocked on: signed checkpoints (R1.3) and the verify command (R1.4).
    // Chain-only verification structurally cannot pass this; see the live
    // demonstration below.
  });

  it.skip('TSA unreachable: events still record, checkpoint queued, verify exits 2 "cannot verify anchor" and never reports clean', () => {
    // Blocked on: R1.3 anchoring and its offline queue.
  });
});

describe('the gap those tests close, demonstrated live', () => {
  it('a recomputed chain passes chain-only verification today', () => {
    // Build a chain, drop three events, re-seal from genesis with the project's
    // own hash function. No secret is needed because no input is secret.
    const original: RecordedEvent[] = [];
    let prev = GENESIS_PREV_HASH;
    for (let i = 0; i < 12; i++) {
      const e = buildEvent(
        {
          actor: { human: 'mallory', agent_id: 'spiffe://orisan/agent/x', tool: 'shell' },
          kind: i === 5 ? 'flag' : 'tool_call',
          target: i === 5 ? 'shell.exec' : `tool.${i}`,
          args_digest: null,
          payload_ref: null,
          outcome: i === 5 ? 'flagged: credential exfiltration' : 'ok',
          duration_ms: 1,
        },
        i,
        prev,
      );
      original.push(e);
      prev = e.hash;
    }
    expect(verifyChain(original)).toEqual([]);

    const kept = original.filter((e) => e.kind !== 'flag').slice(0, 9);
    let p = GENESIS_PREV_HASH;
    const forged = kept.map((e, i) => {
      const base = { ...e, seq: i, prev_hash: p };
      const { hash: _drop, ...rest } = base;
      const sealed = { ...base, hash: computeEventHash(rest as Omit<RecordedEvent, 'hash'>) };
      p = sealed.hash;
      return sealed;
    });

    // The incriminating record is gone and the chain reports perfectly clean.
    expect(forged.some((e) => e.kind === 'flag')).toBe(false);
    expect(verifyChain(forged)).toEqual([]);

    // This is not a bug in verifyChain. It is the reason R1.3 exists, and the
    // reason no output in this repo may call the chain alone tamper-proof.
  });
});

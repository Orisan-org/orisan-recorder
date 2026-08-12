/**
 * External witness — the only thing that detects tail truncation.
 *
 * Job 3 made the checkpoint log a chain, which catches holes, poison pills and
 * erasure. It cannot catch A1: delete the trailing events, the checkpoint
 * covering them, and its anchors, and what remains is a valid prefix —
 * contiguous indexes from 0, head equal to the highest anchored seq. Nothing
 * inside the log distinguishes that from a log that legitimately ended earlier.
 *
 * This is not a gap in our implementation; it is a property of self-held logs.
 * A hash chain proves integrity relative to a head someone already holds. If
 * nobody outside the operator ever saw a head, there is no "already held" head
 * to be relative to. Our own competitor teardown recorded exactly this, and it
 * is the one capability that survived the attack there.
 *
 * So: a witness line is (index, seq_to, link_hash) and nothing else. No event
 * content, no payloads, no arguments — a witness learns how much happened, not
 * what. That is what makes it safe to hand to a customer or a second machine,
 * which is the entire point: the file must live somewhere the operator cannot
 * silently rewrite. Kept inside the log directory it proves nothing, and
 * verify says so.
 */

import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, writeSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import { checkpointLinkHash, type SignedCheckpoint } from './checkpoint.js';

export interface WitnessEntry {
  v: 1;
  index: number;
  seq_to: number;
  /** checkpointLinkHash of the checkpoint at `index`. */
  link_hash: string;
  observed_at: string;
}

/** Append one observation. Durable: a witness that loses its tail is useless. */
export function witnessCheckpoint(path: string, cp: SignedCheckpoint, now: Date = new Date()): WitnessEntry {
  const entry: WitnessEntry = {
    v: 1,
    index: cp.index,
    seq_to: cp.seq_to,
    link_hash: checkpointLinkHash(cp),
    observed_at: now.toISOString(),
  };
  mkdirSync(dirname(resolve(path)), { recursive: true });
  const fd = openSync(path, 'a');
  try {
    const line = Buffer.from(`${JSON.stringify(entry)}\n`, 'utf8');
    let w = 0;
    while (w < line.length) w += writeSync(fd, line, w, line.length - w);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  return entry;
}

export function readWitness(path: string): WitnessEntry[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as WitnessEntry);
}

export interface WitnessBreak {
  reason: 'checkpoint_missing' | 'link_mismatch' | 'witness_ahead_of_log';
  index: number;
  message: string;
}

/**
 * Compare a witness log against the checkpoints actually present.
 *
 * Every checkpoint the witness saw must still be present with the same link
 * hash. A witness entry with no corresponding checkpoint is truncation; a
 * differing link hash is a rewrite.
 */
export function verifyAgainstWitness(
  checkpoints: readonly SignedCheckpoint[],
  witness: readonly WitnessEntry[],
): WitnessBreak[] {
  const breaks: WitnessBreak[] = [];
  const byIndex = new Map(checkpoints.map((c) => [c.index, c]));

  for (const w of witness) {
    const cp = byIndex.get(w.index);
    if (!cp) {
      breaks.push({
        reason: 'checkpoint_missing',
        index: w.index,
        message:
          `the witness observed checkpoint ${w.index} (up to seq ${w.seq_to}) but it is not in ` +
          'the log; events after the surviving checkpoints were removed',
      });
      continue;
    }
    const actual = checkpointLinkHash(cp);
    if (actual !== w.link_hash) {
      breaks.push({
        reason: 'link_mismatch',
        index: w.index,
        message:
          `checkpoint ${w.index} hashes to ${actual.slice(0, 16)}… but the witness recorded ` +
          `${w.link_hash.slice(0, 16)}…; it was rewritten after being witnessed`,
      });
    }
  }
  return breaks;
}

/** Highest checkpoint index the witness ever saw, or -1. */
export function highestWitnessedIndex(witness: readonly WitnessEntry[]): number {
  return witness.length ? Math.max(...witness.map((w) => w.index)) : -1;
}

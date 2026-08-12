/**
 * R1.3 — Merkle tree over event hashes, RFC 6962 (Certificate Transparency).
 *
 * Two details are load-bearing and both are reasons to follow the RFC rather
 * than improvise:
 *
 * 1. Domain separation. Leaves are hashed under a 0x00 prefix and internal
 *    nodes under 0x01. Without it, an internal node's preimage can be passed
 *    off as a leaf, letting an attacker present an interior digest as if it
 *    were a recorded event (the classic second-preimage attack on naive
 *    Merkle trees).
 *
 * 2. Odd nodes are PROMOTED, never duplicated. Bitcoin duplicates the last
 *    node when a level has an odd count, which makes two different leaf lists
 *    produce the same root (CVE-2012-2459). For an audit log that is fatal:
 *    it would let a list of events be swapped for a different list with a
 *    matching checkpoint. RFC 6962 splits at the largest power of two below n
 *    instead, and every distinct leaf list gets a distinct root.
 */

import { createHash } from 'node:crypto';

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

function sha256(...parts: Buffer[]): Buffer {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
}

/** MTH({}) — the hash of the empty string, per RFC 6962 section 2.1. */
export function emptyRoot(): Buffer {
  return createHash('sha256').digest();
}

export function leafHash(eventHashHex: string): Buffer {
  if (!/^[0-9a-f]{64}$/.test(eventHashHex)) throw new Error(`not a sha256 hex digest: ${eventHashHex}`);
  return sha256(LEAF_PREFIX, Buffer.from(eventHashHex, 'hex'));
}

/** Largest power of two strictly less than n. */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function mth(leaves: readonly Buffer[]): Buffer {
  if (leaves.length === 0) return emptyRoot();
  if (leaves.length === 1) return leaves[0]!;
  const k = splitPoint(leaves.length);
  return sha256(NODE_PREFIX, mth(leaves.slice(0, k)), mth(leaves.slice(k)));
}

/** Merkle root over a list of event hashes, as lowercase hex. */
export function merkleRoot(eventHashesHex: readonly string[]): string {
  return mth(eventHashesHex.map(leafHash)).toString('hex');
}

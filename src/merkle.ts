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

/**
 * The same RFC 6962 root, computed one leaf at a time.
 *
 * `merkleRoot` needs every leaf in an array, which is fine for a checkpoint
 * being cut and fatal for verifying a large log — issue #2 measured 691 MB of
 * peak RSS on a 300k-event log because verify materialised all of it.
 *
 * This holds only the roots of completed perfect subtrees: at most one per bit
 * set in the leaf count, so O(log n) hashes, about 18 of them for a log of a
 * million events. Memory does not grow with the log.
 *
 * WHY IT IS THE SAME TREE. RFC 6962 splits at the largest power of two below
 * n, so the left subtree is always perfect and the right recurses the same
 * way. That decomposes any n into perfect subtrees whose sizes are exactly the
 * set bits of n, most significant first, combined right to left — which is
 * precisely what this stack produces. Odd nodes are promoted rather than
 * duplicated here too: a lone subtree is carried up untouched.
 *
 * That argument is worth exactly nothing on its own, so
 * test/merkle.test.ts asserts byte-identical roots against `merkleRoot` for
 * every leaf count from 0 to 300 and for sizes around each power of two.
 */
export class MerkleAccumulator {
  /** Completed perfect subtrees, sizes strictly decreasing towards the top. */
  private readonly stack: { size: number; hash: Buffer }[] = [];
  private n = 0;

  /** Add one event hash, as lowercase sha256 hex. */
  push(eventHashHex: string): void {
    this.n++;
    let node = { size: 1, hash: leafHash(eventHashHex) };
    for (;;) {
      const top = this.stack[this.stack.length - 1];
      if (!top || top.size !== node.size) break;
      this.stack.pop();
      node = { size: top.size * 2, hash: sha256(NODE_PREFIX, top.hash, node.hash) };
    }
    this.stack.push(node);
  }

  get count(): number { return this.n; }

  /** The root so far. Non-destructive: more leaves may be pushed afterwards. */
  root(): string {
    if (this.n === 0) return emptyRoot().toString('hex');
    // Right to left: the rightmost (smallest) subtree is the innermost right
    // child, exactly as the recursive split builds it.
    let acc = this.stack[this.stack.length - 1]!.hash;
    for (let i = this.stack.length - 2; i >= 0; i--) {
      acc = sha256(NODE_PREFIX, this.stack[i]!.hash, acc);
    }
    return acc.toString('hex');
  }
}

import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { MerkleAccumulator, emptyRoot, leafHash, merkleRoot } from '../src/merkle.js';

const h = (s: string) => createHash('sha256').update(s).digest('hex');
const hashes = (n: number) => [...Array(n).keys()].map((i) => h(`event-${i}`));

describe('RFC 6962 conformance', () => {
  it('empty tree is the hash of the empty string', () => {
    expect(merkleRoot([])).toBe(emptyRoot().toString('hex'));
    expect(merkleRoot([])).toBe(createHash('sha256').digest('hex'));
  });

  it('single leaf root is the leaf hash, not the bare event hash', () => {
    const e = h('only');
    expect(merkleRoot([e])).toBe(leafHash(e).toString('hex'));
    expect(merkleRoot([e])).not.toBe(e);
  });

  it('two leaves combine under the internal-node prefix', () => {
    const [a, b] = [h('a'), h('b')];
    const expected = createHash('sha256')
      .update(Buffer.from([0x01]))
      .update(leafHash(a))
      .update(leafHash(b))
      .digest('hex');
    expect(merkleRoot([a, b])).toBe(expected);
  });
});

describe('properties an audit log depends on', () => {
  it('is deterministic', () => {
    expect(merkleRoot(hashes(37))).toBe(merkleRoot(hashes(37)));
  });

  it('order matters', () => {
    const list = hashes(8);
    const swapped = [...list];
    [swapped[2], swapped[3]] = [swapped[3]!, swapped[2]!];
    expect(merkleRoot(swapped)).not.toBe(merkleRoot(list));
  });

  it('any single changed leaf changes the root, at every size', () => {
    for (const n of [1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 100]) {
      const list = hashes(n);
      for (const i of [0, Math.floor(n / 2), n - 1]) {
        const m = [...list];
        m[i] = h('tampered');
        expect(merkleRoot(m), `n=${n} i=${i}`).not.toBe(merkleRoot(list));
      }
    }
  });

  it('dropping a leaf changes the root', () => {
    const list = hashes(9);
    expect(merkleRoot(list.slice(0, 8))).not.toBe(merkleRoot(list));
  });

  it('CVE-2012-2459: an odd tail is promoted, not duplicated', () => {
    // Under Bitcoin-style duplication these two collide. They must not here.
    const three = hashes(3);
    const withDupTail = [...three, three[2]!];
    expect(merkleRoot(withDupTail)).not.toBe(merkleRoot(three));
  });

  it('no leaf list can be confused with an internal node', () => {
    // A leaf whose value equals an internal digest must not produce that digest.
    const [a, b] = [h('a'), h('b')];
    const internal = merkleRoot([a, b]);
    expect(merkleRoot([internal])).not.toBe(internal);
  });

  it('rejects anything that is not a sha256 hex digest', () => {
    expect(() => merkleRoot(['deadbeef'])).toThrow(/not a sha256 hex digest/);
    expect(() => merkleRoot(['A'.repeat(64)])).toThrow(/not a sha256 hex digest/);
  });
});

describe('MerkleAccumulator — the streaming root', () => {
  const h = (i: number): string => createHash('sha256').update(`event-${i}`).digest('hex');

  it('matches merkleRoot for every leaf count from 0 to 300', () => {
    // The whole justification for a second implementation is that it produces
    // the same tree. Asserted exhaustively rather than argued.
    for (let n = 0; n <= 300; n++) {
      const leaves = Array.from({ length: n }, (_, i) => h(i));
      const acc = new MerkleAccumulator();
      for (const leaf of leaves) acc.push(leaf);
      expect(acc.root(), `n=${n}`).toBe(merkleRoot(leaves));
      expect(acc.count).toBe(n);
    }
  });

  it('matches around every power of two up to 4096, where the split lands', () => {
    for (let p = 1; p <= 4096; p *= 2) {
      for (const n of [p - 1, p, p + 1]) {
        if (n < 0) continue;
        const leaves = Array.from({ length: n }, (_, i) => h(i));
        const acc = new MerkleAccumulator();
        for (const leaf of leaves) acc.push(leaf);
        expect(acc.root(), `n=${n}`).toBe(merkleRoot(leaves));
      }
    }
  });

  it('holds O(log n) subtrees, not O(n)', () => {
    const acc = new MerkleAccumulator();
    for (let i = 0; i < 100_000; i++) acc.push(h(i));
    // 100000 = 0b11000011010100000 — 6 bits set, so 6 retained subtrees.
    const stack = (acc as unknown as { stack: unknown[] }).stack;
    expect(stack.length).toBe(6);
    expect(stack.length).toBeLessThan(20);
  });

  it('can be read mid-stream and continued', () => {
    const leaves = Array.from({ length: 50 }, (_, i) => h(i));
    const acc = new MerkleAccumulator();
    for (const leaf of leaves.slice(0, 20)) acc.push(leaf);
    expect(acc.root()).toBe(merkleRoot(leaves.slice(0, 20)));
    for (const leaf of leaves.slice(20)) acc.push(leaf);
    expect(acc.root()).toBe(merkleRoot(leaves));
  });

  it('is empty-safe and single-leaf-safe', () => {
    expect(new MerkleAccumulator().root()).toBe(merkleRoot([]));
    const one = new MerkleAccumulator();
    one.push(h(0));
    expect(one.root()).toBe(merkleRoot([h(0)]));
  });

  it('rejects anything that is not a sha256 digest, as merkleRoot does', () => {
    expect(() => new MerkleAccumulator().push('nope')).toThrow(/not a sha256 hex digest/);
  });
});

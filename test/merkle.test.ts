import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { emptyRoot, leafHash, merkleRoot } from '../src/merkle.js';

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

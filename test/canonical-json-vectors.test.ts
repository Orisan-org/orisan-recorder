/**
 * Cross-language conformance vectors for canonicalJson().
 *
 * src/schema.ts is the reference implementation. These vectors exist so a Go or
 * Python port can assert byte-identical canonical output and hashes against the
 * same fixture, because the chain is only portable if every implementation
 * agrees on the exact bytes.
 *
 * The fixture is read at module load, not inside a test: a missing or
 * unparseable file must fail collection rather than quietly registering zero
 * tests. `it.each([])` registers nothing and a suite that asserts nothing is
 * green, which is the failure mode this file is written to avoid.
 */

import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { canonicalJson } from '../src/schema.js';

interface Vector {
  name: string;
  why: string;
  input: unknown;
  canonical_json: string;
  sha256: string;
}

interface VectorFile {
  spec: string;
  spec_version: string;
  vectors: Vector[];
}

const FIXTURE = fileURLToPath(new URL('./fixtures/canonical-json-vectors.json', import.meta.url));

const suite = JSON.parse(readFileSync(FIXTURE, 'utf8')) as VectorFile;
const vectors: Vector[] = Array.isArray(suite.vectors) ? suite.vectors : [];

/**
 * The count this file is known to cover. Asserted as a floor rather than just
 * "> 0" so that deleting vectors is as loud as emptying the file — a check that
 * silently shrinks its own scope is not a check. Raise it when adding vectors.
 */
const MIN_VECTORS = 20;

const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

describe('canonical JSON conformance vectors', () => {
  it('loads a fixture that actually contains vectors', () => {
    expect(suite.spec).toBe('orisan-canonical-json');
    expect(vectors.length).toBeGreaterThanOrEqual(MIN_VECTORS);
  });

  it('every vector is internally consistent (its hash matches its own string)', () => {
    // Guards against a hand-edited fixture whose string and hash disagree, which
    // would otherwise show up as a confusing failure against the implementation.
    for (const v of vectors) {
      expect(sha256(v.canonical_json), `${v.name}: fixture hash does not match its own canonical_json`).toBe(v.sha256);
    }
  });

  it.each(vectors.map((v) => [v.name, v] as const))('%s', (_name, v) => {
    const actual = canonicalJson(v.input);
    expect(actual, v.why).toBe(v.canonical_json);
    expect(sha256(actual), v.why).toBe(v.sha256);
  });

  it('the vector cases above actually ran', () => {
    // A positive control for the it.each above: if `vectors` were ever empty,
    // it.each registers no cases and contributes no assertions.
    expect(vectors.map((v) => v.name)).toContain('proto_key');
    expect(vectors.map((v) => v.name)).toContain('key_sorting_astral');
  });

  it('rejects a deliberately wrong expectation', () => {
    // Synthetic positive: proves the comparison can fail, so a green run above
    // means the vectors matched rather than that nothing was compared.
    const actual = canonicalJson({ z: 1, a: 2 });
    expect(actual).toBe('{"a":2,"z":1}');
    expect(actual).not.toBe('{"z":1,"a":2}');
    expect(sha256(actual)).not.toBe(sha256('{"z":1,"a":2}'));
  });
});

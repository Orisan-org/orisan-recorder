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

/**
 * sha256 of the fixture's raw bytes, as generated. Pinned HERE and not in the
 * fixture, because a checksum a file carries about itself is not a control: an
 * edit updates both halves and the pair still agrees.
 *
 * The vectors are an oracle. Editing one to make a failing test pass inverts
 * what the test is for — it makes the implementation define correctness instead
 * of being checked against it. Any hand-repair of the fixture, including one
 * that only fixes an encoding accident, changes the oracle and must be a
 * deliberate, reviewed act: regenerate with the generator, then update this pin.
 */
const ORACLE_SHA256 = '78e397c9f79788d3ef2c5cadda225d573046e7dce4349826f0c400672160a327';
const ORACLE_BYTES = 8953;

// Read as BYTES, and hash before parsing. Hashing a re-serialised parse would
// check a round-trip through this process, not the file on disk.
const raw = readFileSync(FIXTURE);
const rawSha256 = createHash('sha256').update(raw).digest('hex');

const suite = JSON.parse(raw.toString('utf8')) as VectorFile;
const vectors: Vector[] = Array.isArray(suite.vectors) ? suite.vectors : [];

/**
 * The count this file is known to cover. Asserted as a floor rather than just
 * "> 0" so that deleting vectors is as loud as emptying the file — a check that
 * silently shrinks its own scope is not a check. Raise it when adding vectors.
 */
const MIN_VECTORS = 20;

const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

describe('canonical JSON conformance vectors', () => {
  it('the oracle has not been modified', () => {
    expect(
      rawSha256,
      `THE ORACLE WAS MODIFIED.\n` +
        `  test/fixtures/canonical-json-vectors.json no longer matches its pinned sha256.\n` +
        `  expected ${ORACLE_SHA256} (${ORACLE_BYTES} bytes)\n` +
        `  actual   ${rawSha256} (${raw.length} bytes)\n` +
        `\n` +
        `  These vectors are the oracle this implementation is checked against.\n` +
        `  If a vector fails, the finding is about canonicalJson() or about the\n` +
        `  vector's provenance — it is never fixed by editing the fixture, which\n` +
        `  would make the implementation define its own correctness.\n` +
        `  To change the vectors legitimately: regenerate with the generator, then\n` +
        `  update ORACLE_SHA256 and ORACLE_BYTES in this file as a reviewed change.`,
    ).toBe(ORACLE_SHA256);
    expect(raw.length).toBe(ORACLE_BYTES);
  });

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

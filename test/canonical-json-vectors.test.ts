/**
 * Cross-language conformance vectors for canonicalJson().
 *
 * src/schema.ts is the reference implementation. These vectors exist so a Go or
 * Python port can assert byte-identical canonical output and hashes against the
 * same fixture, because the chain is only portable if every implementation
 * agrees on the exact bytes.
 *
 * The fixture is generated, never hand-edited: scripts/generate_vectors.py
 * writes it and rewriting it by hand is how an oracle quietly becomes a mirror
 * of whatever the implementation currently does.
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

/**
 * A value canonicalJson does NOT reject.
 *
 * These were written expecting canonicalJson to throw. It does not: it is
 * JSON.stringify underneath, which coerces. NaN and both infinities collapse to
 * "null", -0 to "0", and floats serialise as-is. They are recorded as measured
 * behaviour rather than as an intention, so a port matches the reference instead
 * of matching what someone hoped the reference did.
 *
 * They cannot be JSON literals — JSON has no NaN, no Infinity, and cannot tell
 * -0 from 0 — so the value is named by `build` and constructed in-language here.
 */
interface Coercion {
  name: string;
  why: string;
  build: string;
  emits: string;
}

interface VectorFile {
  spec: string;
  spec_version: string;
  vectors: Vector[];
  coercions: Coercion[];
}

const FIXTURE = fileURLToPath(new URL('./fixtures/canonical-json-vectors.json', import.meta.url));

/**
 * sha256 of the fixture's raw bytes, as generated. Pinned HERE and not in the
 * fixture, because a checksum a file carries about itself is not a control: an
 * edit updates both halves and the pair still agrees.
 *
 * The vectors are an oracle. Editing one to make a failing test pass inverts
 * what the test is for — it makes the implementation define correctness instead
 * of being checked against it. Any change to the fixture must be a deliberate,
 * reviewed act: edit scripts/generate_vectors.py, re-run it, then update this
 * pin in the same commit.
 */
const ORACLE_SHA256 = 'a25dfeab778085c156e6200b52dd56cac45da0e1d0947ffb851705e1978bc016';
const ORACLE_BYTES = 11967;

// Read as BYTES, and hash before parsing. Hashing a re-serialised parse would
// check a round-trip through this process, not the file on disk.
const raw = readFileSync(FIXTURE);
const rawSha256 = createHash('sha256').update(raw).digest('hex');

const suite = JSON.parse(raw.toString('utf8')) as VectorFile;
const vectors: Vector[] = Array.isArray(suite.vectors) ? suite.vectors : [];
const coercions: Coercion[] = Array.isArray(suite.coercions) ? suite.coercions : [];

/**
 * Floors, not "> 0". A check that silently shrinks its own scope is not a
 * check, so deleting entries has to be as loud as emptying the file. Raise
 * these when adding to the fixture.
 */
const MIN_VECTORS = 20;
const MIN_COERCIONS = 5;

/**
 * Execution ledger. Presence in the file is not execution: a filtered, skipped
 * or unbuildable entry would otherwise sit in the fixture looking covered while
 * asserting nothing. Every entry must add its name here, and the last test
 * reconciles both ledgers against the file.
 */
const ranVectors = new Set<string>();
const ranCoercions = new Set<string>();

const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

/** Construct a value JSON cannot carry. Unknown kinds throw rather than skip. */
function buildValue(kind: string): unknown {
  switch (kind) {
    case 'NaN':
      return NaN;
    case 'Infinity':
      return Infinity;
    case '-Infinity':
      return -Infinity;
    case '-0':
      return -0;
    case 'float':
      return 1.5;
    default:
      throw new Error(`unknown coercion build kind: ${kind}`);
  }
}

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
        `  To change the vectors legitimately: edit scripts/generate_vectors.py,\n` +
        `  re-run it, and update ORACLE_SHA256 and ORACLE_BYTES in this file as a\n` +
        `  reviewed change in the same commit.`,
    ).toBe(ORACLE_SHA256);
    expect(raw.length).toBe(ORACLE_BYTES);
  });

  it('loads a fixture that actually contains vectors and coercions', () => {
    expect(suite.spec).toBe('orisan-canonical-json');
    expect(vectors.length).toBeGreaterThanOrEqual(MIN_VECTORS);
    expect(coercions.length).toBeGreaterThanOrEqual(MIN_COERCIONS);
  });

  it('every vector is internally consistent (its hash matches its own string)', () => {
    // Guards against a hand-edited fixture whose string and hash disagree, which
    // would otherwise show up as a confusing failure against the implementation.
    for (const v of vectors) {
      expect(sha256(v.canonical_json), `${v.name}: fixture hash does not match its own canonical_json`).toBe(v.sha256);
    }
  });

  it.each(vectors.map((v) => [v.name, v] as const))('vector: %s', (name, v) => {
    const actual = canonicalJson(v.input);
    expect(actual, v.why).toBe(v.canonical_json);
    expect(sha256(actual), v.why).toBe(v.sha256);
    ranVectors.add(name);
  });

  it.each(coercions.map((c) => [c.name, c] as const))('coercion: %s', (name, c) => {
    // Asserted as an equality against measured output, NOT as a throw.
    // canonicalJson does not refuse these; recording them as refusals would
    // freeze a claim the code contradicts.
    expect(canonicalJson(buildValue(c.build)), c.why).toBe(c.emits);
    ranCoercions.add(name);
  });

  it('every entry in both arrays produced a result', () => {
    // Runs last, and is the reason the ledgers exist: an entry sitting in the
    // fixture that never executed must fail the suite rather than inflate the
    // apparent coverage.
    expect([...ranVectors].sort()).toEqual(vectors.map((v) => v.name).sort());
    expect([...ranCoercions].sort()).toEqual(coercions.map((c) => c.name).sort());
    expect(ranVectors.size).toBeGreaterThanOrEqual(MIN_VECTORS);
    expect(ranCoercions.size).toBeGreaterThanOrEqual(MIN_COERCIONS);
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

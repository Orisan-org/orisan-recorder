import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

import {
  PUBLIC_KEY_FILENAME,
  anchorDigest,
  appendCheckpoint,
  buildCheckpoint,
  generateSigningKey,
  loadSigningKey,
  readCheckpoints,
  signCheckpoint,
  verifyCheckpointSignature,
  checkpointBody,
} from '../src/checkpoint.js';

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'orisan-cp-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

const h = (s: string) => createHash('sha256').update(s).digest('hex');
const hashes = (n: number, tag = 'e') => [...Array(n).keys()].map((i) => h(`${tag}-${i}`));

describe('signing key', () => {
  it('is written owner-only, with the public key readable beside it', () => {
    const kf = generateSigningKey(dir);
    expect(statSync(join(dir, 'signing.key')).mode & 0o777).toBe(0o600);
    expect(statSync(join(dir, PUBLIC_KEY_FILENAME)).mode & 0o777).toBe(0o644);
    expect(kf.public_key_pem).toMatch(/^-----BEGIN PUBLIC KEY-----/);
  });

  it('refuses a group-readable signing key', () => {
    generateSigningKey(dir);
    chmodSync(join(dir, 'signing.key'), 0o640);
    expect(() => loadSigningKey(dir)).toThrow(/owner-only/);
  });
});

describe('checkpoint signing', () => {
  it('signs and verifies a range', () => {
    const kf = generateSigningKey(dir);
    const cp = buildCheckpoint(hashes(500), 0, 'interval', kf);
    expect(cp.seq_from).toBe(0);
    expect(cp.seq_to).toBe(499);
    expect(cp.count).toBe(500);
    expect(verifyCheckpointSignature(cp, kf.public_key_pem)).toBe(true);
  });

  it('rejects a checkpoint whose root was edited', () => {
    const kf = generateSigningKey(dir);
    const cp = buildCheckpoint(hashes(10), 0, 'interval', kf);
    const forged = { ...cp, merkle_root: h('different') };
    expect(verifyCheckpointSignature(forged, kf.public_key_pem)).toBe(false);
  });

  it('rejects edits to every signed field', () => {
    const kf = generateSigningKey(dir);
    const cp = buildCheckpoint(hashes(10), 0, 'interval', kf);
    for (const mutated of [
      { ...cp, seq_from: 1 },
      { ...cp, seq_to: 8 },
      { ...cp, count: 9 },
      { ...cp, created_at: '2030-01-01T00:00:00.000Z' },
      { ...cp, reason: 'manual' as const },
      { ...cp, key_id: 'f'.repeat(32) },
    ]) {
      expect(verifyCheckpointSignature(mutated, kf.public_key_pem)).toBe(false);
    }
  });

  it('rejects a signature from a different key', () => {
    const a = generateSigningKey(dir);
    const otherDir = mkdtempSync(join(tmpdir(), 'orisan-cp2-'));
    try {
      const b = generateSigningKey(otherDir);
      const cp = buildCheckpoint(hashes(5), 0, 'interval', b);
      expect(verifyCheckpointSignature(cp, a.public_key_pem)).toBe(false);
      expect(verifyCheckpointSignature(cp, b.public_key_pem)).toBe(true);
    } finally { rmSync(otherDir, { recursive: true, force: true }); }
  });

  it('refuses to checkpoint an empty range', () => {
    const kf = generateSigningKey(dir);
    expect(() => buildCheckpoint([], 0, 'interval', kf)).toThrow(/empty range/);
  });

  it('a garbage signature is false, not a thrown error', () => {
    const kf = generateSigningKey(dir);
    const cp = buildCheckpoint(hashes(3), 0, 'interval', kf);
    expect(verifyCheckpointSignature({ ...cp, signature: 'not-base64!!' }, kf.public_key_pem)).toBe(false);
    expect(verifyCheckpointSignature(cp, 'not a pem')).toBe(false);
  });
});

describe('third-party verifiability', () => {
  it('the public key is a standard SPKI PEM openssl can parse', () => {
    const kf = generateSigningKey(dir);
    const out = execFileSync('openssl', ['pkey', '-pubin', '-in', join(dir, PUBLIC_KEY_FILENAME), '-text', '-noout'], {
      encoding: 'utf8',
    });
    expect(out).toMatch(/ED25519/i);
  });
});

describe('anchor digest', () => {
  it('covers the signature, not just the root', () => {
    const kf = generateSigningKey(dir);
    const cp = buildCheckpoint(hashes(4), 0, 'interval', kf);
    // Re-sign the identical body; Ed25519 is deterministic so the signature is
    // the same and so is the digest. Change the body and the digest must move.
    const resigned = signCheckpoint(checkpointBody(cp), kf);
    expect(anchorDigest(resigned).equals(anchorDigest(cp))).toBe(true);

    const other = buildCheckpoint(hashes(4, 'x'), 0, 'interval', kf);
    expect(anchorDigest(other).equals(anchorDigest(cp))).toBe(false);
  });

  it('is 32 bytes', () => {
    const kf = generateSigningKey(dir);
    expect(anchorDigest(buildCheckpoint(hashes(2), 0, 'interval', kf))).toHaveLength(32);
  });
});

describe('checkpoint log', () => {
  it('appends and reads back in order', () => {
    const kf = generateSigningKey(dir);
    appendCheckpoint(dir, buildCheckpoint(hashes(3, 'a'), 0, 'interval', kf));
    appendCheckpoint(dir, buildCheckpoint(hashes(3, 'b'), 3, 'session_end', kf));
    const cps = readCheckpoints(dir);
    expect(cps).toHaveLength(2);
    expect(cps[0]!.seq_from).toBe(0);
    expect(cps[1]!.seq_from).toBe(3);
    expect(cps.every((c) => verifyCheckpointSignature(c, kf.public_key_pem))).toBe(true);
  });

  it('returns empty for a directory with no checkpoints', () => {
    expect(readCheckpoints(dir)).toEqual([]);
  });

  it('survives a hand-edited file being detected downstream', () => {
    const kf = generateSigningKey(dir);
    appendCheckpoint(dir, buildCheckpoint(hashes(3), 0, 'interval', kf));
    const path = join(dir, 'checkpoints.jsonl');
    const cp = JSON.parse(readFileSync(path, 'utf8').trim()) as Record<string, unknown>;
    cp['merkle_root'] = h('swapped');
    writeFileSync(path, `${JSON.stringify(cp)}\n`);
    expect(verifyCheckpointSignature(readCheckpoints(dir)[0]!, kf.public_key_pem)).toBe(false);
  });
});

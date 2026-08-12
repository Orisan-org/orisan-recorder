import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { PAYLOAD_DIRNAME, generateKeyFile, loadKeyFile, openPayload, sealPayload } from '../src/payloads.js';

let dir: string;
let keyPath: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'orisan-pay-'));
  keyPath = join(dir, 'recorder.key');
});
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

describe('key file handling', () => {
  it('declares the primitive it was made for', () => {
    const kf = generateKeyFile(keyPath);
    expect(kf.alg).toBe('crypto_box_seal');
    expect(Buffer.from(kf.public_key, 'base64')).toHaveLength(32);
    expect(Buffer.from(kf.private_key!, 'base64')).toHaveLength(32);
  });

  it('refuses a key file whose algorithm it does not implement', () => {
    const kf = generateKeyFile(keyPath);
    writeFileSync(keyPath, JSON.stringify({ ...kf, alg: 'rot13' }), { mode: 0o600 });
    expect(() => loadKeyFile(keyPath)).toThrow(/unsupported key algorithm/);
  });

  it('writes owner-only and round-trips through load', () => {
    const created = generateKeyFile(keyPath);
    expect(statSync(keyPath).mode & 0o777).toBe(0o600);
    const loaded = loadKeyFile(keyPath);
    expect(loaded.kid).toBe(created.kid);
    expect(loaded.public_key).toBe(created.public_key);
  });

  it('refuses a group- or world-readable key file', () => {
    generateKeyFile(keyPath);
    chmodSync(keyPath, 0o644);
    expect(() => loadKeyFile(keyPath)).toThrow(/must not be group- or world-accessible/);
  });

  it('refuses a key file whose kid does not match its public key', () => {
    const kf = generateKeyFile(keyPath);
    writeFileSync(keyPath, JSON.stringify({ ...kf, kid: 'f'.repeat(32) }), { mode: 0o600 });
    expect(() => loadKeyFile(keyPath)).toThrow(/kid does not match/);
  });
});

describe('sealing and opening', () => {
  it('round-trips a payload', () => {
    const kf = generateKeyFile(keyPath);
    const secret = JSON.stringify({ prompt: 'fake prompt', token: 'FAKE-NOT-REAL' });
    const ref = sealPayload(dir, kf, secret);
    expect(openPayload(dir, kf, ref).toString('utf8')).toBe(secret);
  });

  it('never writes the plaintext to disk', () => {
    const kf = generateKeyFile(keyPath);
    const marker = 'CANARY-PLAINTEXT-a7f3';
    const ref = sealPayload(dir, kf, `payload containing ${marker}`);
    const blob = readFileSync(join(dir, PAYLOAD_DIRNAME, `${ref}.blob`));
    expect(blob.includes(Buffer.from(marker, 'utf8'))).toBe(false);
  });

  it('is content-addressed: the ref names the blob bytes', () => {
    const kf = generateKeyFile(keyPath);
    const ref = sealPayload(dir, kf, 'x');
    expect(ref).toMatch(/^[0-9a-f]{64}$/);
  });

  it('uses a fresh ephemeral key: same plaintext seals to different blobs', () => {
    const kf = generateKeyFile(keyPath);
    const a = sealPayload(dir, kf, 'identical');
    const b = sealPayload(dir, kf, 'identical');
    expect(a).not.toBe(b);
    expect(openPayload(dir, kf, a).toString()).toBe('identical');
    expect(openPayload(dir, kf, b).toString()).toBe('identical');
  });

  it('rejects a flipped byte in the ciphertext', () => {
    const kf = generateKeyFile(keyPath);
    const ref = sealPayload(dir, kf, 'sensitive fake payload');
    const path = join(dir, PAYLOAD_DIRNAME, `${ref}.blob`);
    const blob = readFileSync(path);
    blob[blob.length - 20] ^= 0x01;
    writeFileSync(path, blob);
    // Caught by content addressing before the cipher is even reached.
    expect(() => openPayload(dir, kf, ref)).toThrow(/does not match its content hash/);
  });

  it('rejects a tampered blob even when renamed to its new content hash', () => {
    // Content addressing is bypassed by the rename; sodium's own authentication
    // is what must refuse here.
    const kf = generateKeyFile(keyPath);
    const ref = sealPayload(dir, kf, 'sensitive fake payload');
    const blob = readFileSync(join(dir, PAYLOAD_DIRNAME, `${ref}.blob`));
    blob[blob.length - 20] ^= 0x01;
    // Attacker recomputes the ref so content addressing passes; GCM must still refuse.
    const newRef = createHash('sha256').update(blob).digest('hex');
    writeFileSync(join(dir, PAYLOAD_DIRNAME, `${newRef}.blob`), blob);
    expect(() => openPayload(dir, kf, newRef)).toThrow();
  });

  it('cannot be opened with a different key', () => {
    const kf = generateKeyFile(keyPath);
    const ref = sealPayload(dir, kf, 'for alice only');
    const otherPath = join(dir, 'other.key');
    const other = generateKeyFile(otherPath);
    expect(() => openPayload(dir, other, ref)).toThrow();
  });

  it('refuses to decrypt with a write-only key file', () => {
    const kf = generateKeyFile(keyPath);
    const ref = sealPayload(dir, kf, 'x');
    const { private_key: _drop, ...writeOnly } = kf;
    expect(() => openPayload(dir, writeOnly, ref)).toThrow(/no private key/);
  });

  it('reports a missing blob rather than returning empty', () => {
    const kf = generateKeyFile(keyPath);
    expect(() => openPayload(dir, kf, 'a'.repeat(64))).toThrow(/not found/);
  });
});

import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  derBoolean, derInteger, derNull, derObjectIdentifier, derOctetString, derSequence,
  encodeLength, readInteger, readTlv,
} from '../src/der.js';
import { buildTimeStampRequest, readResponseStatus, responseHasToken } from '../src/tsa.js';

describe('DER primitives', () => {
  it('encodes short and long lengths', () => {
    expect(encodeLength(0).toString('hex')).toBe('00');
    expect(encodeLength(127).toString('hex')).toBe('7f');
    expect(encodeLength(128).toString('hex')).toBe('8180');
    expect(encodeLength(256).toString('hex')).toBe('820100');
  });

  it('encodes INTEGERs minimally and never as negative', () => {
    expect(derInteger(0).toString('hex')).toBe('020100');
    expect(derInteger(1).toString('hex')).toBe('020101');
    // 0x80 has the high bit set and must be padded, or it reads as -128.
    expect(derInteger(128).toString('hex')).toBe('02020080');
    expect(derInteger(255).toString('hex')).toBe('020200ff');
    expect(() => derInteger(-1)).toThrow(/non-negative/);
  });

  it('encodes the sha256 OID as the standard bytes', () => {
    expect(derObjectIdentifier('2.16.840.1.101.3.4.2.1').toString('hex'))
      .toBe('0609608648016503040201');
  });

  it('encodes NULL, BOOLEAN, OCTET STRING and SEQUENCE', () => {
    expect(derNull().toString('hex')).toBe('0500');
    expect(derBoolean(true).toString('hex')).toBe('0101ff');
    expect(derBoolean(false).toString('hex')).toBe('010100');
    expect(derOctetString(Buffer.from([1, 2])).toString('hex')).toBe('04020102');
    expect(derSequence(derInteger(1)).toString('hex')).toBe('3003020101');
  });
});

describe('DER reader', () => {
  it('round-trips what the encoder produces', () => {
    const seq = derSequence(derInteger(42), derBoolean(true));
    const node = readTlv(seq, 0);
    expect(node.tag).toBe(0x30);
    expect(readInteger(readTlv(seq, node.valueStart))).toBe(42);
  });

  it('rejects indefinite-length and truncated input', () => {
    expect(() => readTlv(Buffer.from([0x30, 0x80, 0x00, 0x00]))).toThrow(/indefinite-length/);
    expect(() => readTlv(Buffer.from([0x30, 0x05, 0x01]))).toThrow(/truncated/);
    expect(() => readTlv(Buffer.from([0x30]))).toThrow(/truncated/);
  });
});

describe('RFC 3161 request, checked against openssl', () => {
  it('ACCEPTANCE: our TimeStampReq is byte-identical to openssl ts -query', () => {
    const dir = mkdtempSync(join(tmpdir(), 'orisan-der-'));
    try {
      const dataPath = join(dir, 'data');
      const payload = Buffer.from('fake checkpoint bytes');
      writeFileSync(dataPath, payload);

      const refPath = join(dir, 'ref.tsq');
      execFileSync('openssl', [
        'ts', '-query', '-data', dataPath, '-sha256', '-cert', '-no_nonce', '-out', refPath,
      ], { stdio: ['ignore', 'ignore', 'ignore'] });

      const ours = buildTimeStampRequest(createHash('sha256').update(payload).digest());
      expect(ours.toString('hex')).toBe(readFileSync(refPath).toString('hex'));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('includes a nonce when asked, and it changes the encoding', () => {
    const d = createHash('sha256').update('x').digest();
    expect(buildTimeStampRequest(d, 12345n).length).toBeGreaterThan(buildTimeStampRequest(d).length);
  });

  it('refuses a digest that is not sha256-sized', () => {
    expect(() => buildTimeStampRequest(Buffer.alloc(20))).toThrow(/32-byte/);
  });
});

describe('RFC 3161 response status', () => {
  /** PKIStatusInfo{status} plus an optional trailing token. */
  const resp = (status: number, withToken: boolean) =>
    derSequence(
      derSequence(derInteger(status)),
      ...(withToken ? [derSequence(derInteger(1))] : []),
    );

  it('reads granted and rejection statuses', () => {
    expect(readResponseStatus(resp(0, true))).toBe(0);
    expect(readResponseStatus(resp(2, false))).toBe(2);
  });

  it('detects presence and absence of a token', () => {
    expect(responseHasToken(resp(0, true))).toBe(true);
    expect(responseHasToken(resp(2, false))).toBe(false);
  });

  it('throws rather than guessing on garbage', () => {
    expect(() => readResponseStatus(Buffer.from([0x04, 0x01, 0x00]))).toThrow(/not a SEQUENCE/);
  });
});

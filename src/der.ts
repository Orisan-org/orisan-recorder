/**
 * Minimal DER encoder/reader — only what RFC 3161 timestamping needs.
 *
 * Hand-rolled rather than shelling out to `openssl ts -query` because the
 * RECORDER must be self-contained: a recorder that cannot write an event
 * because openssl is missing has failed at its one job. The VERIFIER may lean
 * on openssl freely, and does — that asymmetry is deliberate.
 *
 * Scope is intentionally tiny: the handful of universal types in a
 * TimeStampReq, plus enough reading to pull a PKIStatus out of a response.
 * This is not a general ASN.1 library and must not grow into one.
 */

/** Encode a DER length. */
export function encodeLength(n: number): Buffer {
  if (n < 0) throw new Error('negative length');
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>>= 8;
  }
  if (bytes.length > 126) throw new Error('length too large');
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

export function tlv(tag: number, value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeLength(value.length), value]);
}

/** INTEGER, non-negative, minimal encoding with a leading zero when needed. */
export function derInteger(value: number | bigint): Buffer {
  let v = typeof value === 'bigint' ? value : BigInt(value);
  if (v < 0n) throw new Error('only non-negative integers are supported');
  const bytes: number[] = [];
  if (v === 0n) bytes.push(0);
  while (v > 0n) {
    bytes.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  // High bit set would read as negative; prepend a zero byte.
  if ((bytes[0]! & 0x80) !== 0) bytes.unshift(0);
  return tlv(0x02, Buffer.from(bytes));
}

export function derOctetString(value: Buffer): Buffer {
  return tlv(0x04, value);
}

export function derNull(): Buffer {
  return Buffer.from([0x05, 0x00]);
}

export function derBoolean(value: boolean): Buffer {
  return tlv(0x01, Buffer.from([value ? 0xff : 0x00]));
}

export function derSequence(...parts: Buffer[]): Buffer {
  return tlv(0x30, Buffer.concat(parts));
}

/** Encode an OID from dotted form, e.g. "2.16.840.1.101.3.4.2.1". */
export function derObjectIdentifier(dotted: string): Buffer {
  const arcs = dotted.split('.').map((a) => {
    const n = Number.parseInt(a, 10);
    if (!Number.isSafeInteger(n) || n < 0) throw new Error(`bad OID arc: ${a}`);
    return n;
  });
  if (arcs.length < 2) throw new Error('OID needs at least two arcs');
  const body: number[] = [arcs[0]! * 40 + arcs[1]!];
  for (const arc of arcs.slice(2)) {
    const chunks: number[] = [];
    let v = arc;
    do {
      chunks.unshift(v & 0x7f);
      v >>>= 7;
    } while (v > 0);
    for (let i = 0; i < chunks.length - 1; i++) chunks[i]! |= 0x80;
    body.push(...chunks);
  }
  return tlv(0x06, Buffer.from(body));
}

export interface DerNode {
  tag: number;
  /** Offset of the value within the original buffer. */
  valueStart: number;
  length: number;
  value: Buffer;
  /** Offset just past this node. */
  end: number;
}

/** Read one TLV at `offset`. Rejects indefinite-length forms (not valid DER). */
export function readTlv(buf: Buffer, offset = 0): DerNode {
  if (offset + 2 > buf.length) throw new Error('truncated DER: no tag/length');
  const tag = buf[offset]!;
  const first = buf[offset + 1]!;
  let length: number;
  let valueStart: number;

  if (first === 0x80) throw new Error('indefinite-length encoding is not valid DER');
  if ((first & 0x80) === 0) {
    length = first;
    valueStart = offset + 2;
  } else {
    const numBytes = first & 0x7f;
    if (numBytes === 0 || numBytes > 4) throw new Error(`unsupported DER length of ${numBytes} bytes`);
    if (offset + 2 + numBytes > buf.length) throw new Error('truncated DER: length bytes');
    length = 0;
    for (let i = 0; i < numBytes; i++) length = (length << 8) | buf[offset + 2 + i]!;
    valueStart = offset + 2 + numBytes;
  }

  const end = valueStart + length;
  if (end > buf.length) throw new Error('truncated DER: value runs past the buffer');
  return { tag, valueStart, length, value: buf.subarray(valueStart, end), end };
}

/** Read a non-negative INTEGER's value as a JS number. */
export function readInteger(node: DerNode): number {
  if (node.tag !== 0x02) throw new Error(`expected INTEGER, got tag 0x${node.tag.toString(16)}`);
  if (node.value.length === 0) throw new Error('empty INTEGER');
  if (node.value.length > 6) throw new Error('INTEGER too large for a status code');
  let v = 0;
  for (const b of node.value) v = v * 256 + b;
  return v;
}

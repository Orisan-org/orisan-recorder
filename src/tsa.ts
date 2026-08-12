/**
 * R1.3 — RFC 3161 anchoring.
 *
 * A signed checkpoint proves "the key holder asserts this range". It does not
 * prove *when*, and it does not survive the key holder rewriting history and
 * re-signing. Anchoring the checkpoint to a Timestamp Authority the operator
 * does not control turns the assertion into a commitment: this signed
 * checkpoint existed no later than T, attested by a party with no stake.
 *
 * THE RULE, taken from halo-record and adopted deliberately: we never verify
 * our own time proof. Nothing in this file validates a TSA signature. The
 * verifier shells out to `openssl ts -verify` and prints the command it ran,
 * so a reviewer trusts openssl and the TSA's CA rather than any code of ours.
 * The only thing read here is the transport-level PKIStatus, which is a
 * did-the-request-succeed check, not a trust decision.
 *
 * Offline behaviour: recording never depends on the TSA. If it is unreachable
 * the checkpoint is still written and signed; it is simply unanchored, and an
 * unanchored checkpoint is what makes `verify` report cannot-verify (exit 2)
 * rather than clean. A missing anchor is a visible state, never a silent one.
 */

import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, readdirSync, writeSync } from 'node:fs';
import { join } from 'node:path';

import {
  derBoolean,
  derInteger,
  derNull,
  derObjectIdentifier,
  derOctetString,
  derSequence,
  readInteger,
  readTlv,
} from './der.js';
import { anchorDigest, type SignedCheckpoint } from './checkpoint.js';

export const ANCHOR_DIRNAME = 'anchors';
export const DEFAULT_TSA_URL = 'https://freetsa.org/tsr';

const OID_SHA256 = '2.16.840.1.101.3.4.2.1';

/** RFC 3161 PKIStatus values we distinguish. */
export const PKI_STATUS_GRANTED = 0;
export const PKI_STATUS_GRANTED_WITH_MODS = 1;

/**
 * Build a DER TimeStampReq over a sha256 digest.
 *
 *   TimeStampReq ::= SEQUENCE {
 *     version        INTEGER { v1(1) },
 *     messageImprint MessageImprint,
 *     reqPolicy      TSAPolicyId OPTIONAL,
 *     nonce          INTEGER     OPTIONAL,
 *     certReq        BOOLEAN     DEFAULT FALSE,
 *     extensions [0] IMPLICIT Extensions OPTIONAL }
 *
 * certReq is true so the reply carries the TSA certificate chain; without it
 * an auditor needs an out-of-band copy to verify, which defeats the purpose.
 */
export function buildTimeStampRequest(digest: Buffer, nonce?: bigint): Buffer {
  if (digest.length !== 32) throw new Error(`expected a 32-byte sha256 digest, got ${digest.length}`);
  const messageImprint = derSequence(
    derSequence(derObjectIdentifier(OID_SHA256), derNull()),
    derOctetString(digest),
  );
  const parts: Buffer[] = [derInteger(1), messageImprint];
  if (nonce !== undefined) parts.push(derInteger(nonce));
  parts.push(derBoolean(true));
  return derSequence(...parts);
}

/**
 * Read the PKIStatus from a TimeStampResp.
 *
 *   TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken OPTIONAL }
 *   PKIStatusInfo ::= SEQUENCE { status PKIStatus, ... }
 */
export function readResponseStatus(der: Buffer): number {
  const resp = readTlv(der, 0);
  if (resp.tag !== 0x30) throw new Error('TimeStampResp is not a SEQUENCE');
  const statusInfo = readTlv(der, resp.valueStart);
  if (statusInfo.tag !== 0x30) throw new Error('PKIStatusInfo is not a SEQUENCE');
  return readInteger(readTlv(der, statusInfo.valueStart));
}

/** True if the response carries a token after the status block. */
export function responseHasToken(der: Buffer): boolean {
  const resp = readTlv(der, 0);
  const statusInfo = readTlv(der, resp.valueStart);
  return statusInfo.end < resp.end;
}

export interface AnchorRecord {
  v: 1;
  seq_to: number;
  tsa_url: string;
  /** hex sha256 that was submitted; must equal anchorDigest(checkpoint). */
  digest: string;
  received_at: string;
  pki_status: number;
  tsr_file: string;
}

export function anchorPaths(dir: string, seqTo: number): { json: string; tsr: string } {
  const base = join(dir, ANCHOR_DIRNAME, String(seqTo).padStart(8, '0'));
  return { json: `${base}.json`, tsr: `${base}.tsr` };
}

export function hasAnchor(dir: string, seqTo: number): boolean {
  const p = anchorPaths(dir, seqTo);
  return existsSync(p.json) && existsSync(p.tsr);
}

export function readAnchor(dir: string, seqTo: number): AnchorRecord | null {
  const p = anchorPaths(dir, seqTo);
  if (!existsSync(p.json)) return null;
  return JSON.parse(readFileSync(p.json, 'utf8')) as AnchorRecord;
}

export function listAnchoredSeqs(dir: string): number[] {
  const d = join(dir, ANCHOR_DIRNAME);
  if (!existsSync(d)) return [];
  return readdirSync(d)
    .filter((f) => f.endsWith('.tsr'))
    .map((f) => Number.parseInt(f.slice(0, -4), 10))
    .filter((n) => Number.isSafeInteger(n))
    .sort((a, b) => a - b);
}

function writeDurable(path: string, data: Buffer): void {
  const fd = openSync(path, 'w');
  try {
    let w = 0;
    while (w < data.length) w += writeSync(fd, data, w, data.length - w);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

export interface AnchorResult {
  ok: boolean;
  seq_to: number;
  /** Present when ok. */
  record?: AnchorRecord;
  /** Present when not ok — why the anchor could not be obtained. */
  error?: string;
}

export interface AnchorOptions {
  tsaUrl?: string;
  timeoutMs?: number;
  /** Injected in tests so no network is required. */
  fetchImpl?: (url: string, init: { method: string; headers: Record<string, string>; body: Buffer; signal: AbortSignal }) => Promise<{ ok: boolean; status: number; arrayBuffer: () => Promise<ArrayBuffer> }>;
}

/**
 * Anchor one checkpoint. Never throws for an unreachable TSA — an offline TSA
 * is an expected state, and the caller records it as "pending" rather than
 * failing the recording.
 */
export async function anchorCheckpoint(
  dir: string,
  cp: SignedCheckpoint,
  opts: AnchorOptions = {},
): Promise<AnchorResult> {
  const url = opts.tsaUrl ?? DEFAULT_TSA_URL;
  const timeoutMs = opts.timeoutMs ?? 15_000;
  const doFetch = opts.fetchImpl ?? (globalThis.fetch as unknown as NonNullable<AnchorOptions['fetchImpl']>);

  const digest = anchorDigest(cp);
  const request = buildTimeStampRequest(digest);

  let body: Buffer;
  try {
    const res = await doFetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/timestamp-query',
        Accept: 'application/timestamp-reply',
      },
      body: request,
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return { ok: false, seq_to: cp.seq_to, error: `TSA returned HTTP ${res.status}` };
    body = Buffer.from(await res.arrayBuffer());
  } catch (e) {
    return { ok: false, seq_to: cp.seq_to, error: `TSA unreachable: ${(e as Error).message}` };
  }

  let status: number;
  try {
    status = readResponseStatus(body);
  } catch (e) {
    return { ok: false, seq_to: cp.seq_to, error: `malformed TSA response: ${(e as Error).message}` };
  }
  if (status !== PKI_STATUS_GRANTED && status !== PKI_STATUS_GRANTED_WITH_MODS) {
    return { ok: false, seq_to: cp.seq_to, error: `TSA refused the request (PKIStatus ${status})` };
  }
  if (!responseHasToken(body)) {
    return { ok: false, seq_to: cp.seq_to, error: 'TSA response carried no token' };
  }

  const paths = anchorPaths(dir, cp.seq_to);
  mkdirSync(join(dir, ANCHOR_DIRNAME), { recursive: true });
  writeDurable(paths.tsr, body);

  const record: AnchorRecord = {
    v: 1,
    seq_to: cp.seq_to,
    tsa_url: url,
    digest: digest.toString('hex'),
    received_at: new Date().toISOString(),
    pki_status: status,
    tsr_file: `${ANCHOR_DIRNAME}/${String(cp.seq_to).padStart(8, '0')}.tsr`,
  };
  writeDurable(paths.json, Buffer.from(`${JSON.stringify(record, null, 2)}\n`, 'utf8'));
  return { ok: true, seq_to: cp.seq_to, record };
}

/** Checkpoints with no anchor on disk — the offline queue, derived not stored. */
export function pendingAnchors(dir: string, checkpoints: readonly SignedCheckpoint[]): SignedCheckpoint[] {
  return checkpoints.filter((cp) => !hasAnchor(dir, cp.seq_to));
}

/** Try to anchor every pending checkpoint. Returns one result per attempt. */
export async function drainAnchorQueue(
  dir: string,
  checkpoints: readonly SignedCheckpoint[],
  opts: AnchorOptions = {},
): Promise<AnchorResult[]> {
  const results: AnchorResult[] = [];
  for (const cp of pendingAnchors(dir, checkpoints)) {
    results.push(await anchorCheckpoint(dir, cp, opts));
  }
  return results;
}

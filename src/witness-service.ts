/**
 * W1.4 — client for the external witness service.
 *
 * The witness is the only thing that can detect tail truncation, so the client
 * has one non-negotiable rule: THE WITNESS KEY IS PINNED AT REGISTRATION AND
 * NEVER RE-LEARNED. A response signed by any other key is treated as an attack
 * and fails hard. Silently accepting a new key would turn the whole mechanism
 * into theatre — an attacker who can intercept the connection would simply
 * present their own witness and get a clean verdict.
 *
 * The local `witness.ts` (a witness FILE) remains for people who want the
 * weaker, self-hosted version. This is the service.
 */

import { createPublicKey, randomUUID, verify as edVerify } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { canonicalJson } from './schema.js';
import type { SignedCheckpoint, SigningKeyFile } from './checkpoint.js';
import { sign as signWithKey } from './checkpoint-sign.js';

export const WITNESS_CONFIG_FILENAME = 'witness.json';
export const RECEIPTS_DIRNAME = 'receipts';

export interface WitnessConfig {
  v: 1;
  url: string;
  log_id: string;
  /** PINNED at registration. Never updated from a response. */
  witness_pubkey_pem: string;
  registered_at: string;
}

export interface WitnessReceipt {
  log_id: string;
  index: number;
  seq_from: number;
  seq_to: number;
  merkle_root: string;
  witnessed_at: string;
  witness_signature: string;
}

export interface WitnessHead {
  log_id: string;
  latest_index: number;
  latest_seq_to: number;
  merkle_root: string;
  witnessed_at: string;
  conflict: boolean;
  conflict_count: number;
  witness_signature: string;
}

export type FetchLike = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown>; text: () => Promise<string> }>;

function http(): FetchLike {
  return globalThis.fetch as unknown as FetchLike;
}

export function configPath(dir: string): string { return join(dir, WITNESS_CONFIG_FILENAME); }

export function readWitnessConfig(dir: string): WitnessConfig | null {
  const p = configPath(dir);
  if (!existsSync(p)) return null;
  const cfg = JSON.parse(readFileSync(p, 'utf8')) as WitnessConfig;
  if (cfg.v !== 1) throw new Error(`unsupported witness config version: ${String(cfg.v)}`);
  if (!cfg.witness_pubkey_pem?.includes('BEGIN PUBLIC KEY')) throw new Error('witness config has no pinned key');
  return cfg;
}

export function writeWitnessConfig(dir: string, cfg: WitnessConfig): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(configPath(dir), `${JSON.stringify(cfg, null, 2)}\n`, { mode: 0o644 });
}

/** The payload the client signs for a submission. Byte-identical to the service's. */
export function submissionPayload(logId: string, cp: SignedCheckpoint): unknown {
  return {
    log_id: logId,
    index: cp.index,
    seq_from: cp.seq_from,
    seq_to: cp.seq_to,
    merkle_root: cp.merkle_root,
  };
}

/** What the witness signs in a head. Must match the service exactly. */
export function headSignedPayload(h: Omit<WitnessHead, 'witness_signature'>): unknown {
  return {
    log_id: h.log_id,
    latest_index: h.latest_index,
    latest_seq_to: h.latest_seq_to,
    merkle_root: h.merkle_root,
    witnessed_at: h.witnessed_at,
    conflict: h.conflict,
    conflict_count: h.conflict_count,
  };
}

/** Thrown when a response is not signed by the pinned key. Never recoverable. */
export class WitnessKeyMismatch extends Error {
  constructor(what: string) {
    super(
      `witness key mismatch on ${what}: the response was not signed by the pinned witness key. ` +
      'Treat this as an attack — do not re-pin.',
    );
    this.name = 'WitnessKeyMismatch';
  }
}

export function verifyWitnessSignature(pinnedPem: string, payload: unknown, signatureB64: string): boolean {
  try {
    return edVerify(
      null,
      Buffer.from(canonicalJson(payload), 'utf8'),
      createPublicKey(pinnedPem),
      Buffer.from(signatureB64, 'base64'),
    );
  } catch {
    return false;
  }
}

export interface RegisterOptions { url: string; fetchImpl?: FetchLike; logId?: string }

/** Register a new log and PIN the witness key that answers. */
export async function registerLog(
  dir: string,
  signingKey: SigningKeyFile,
  opts: RegisterOptions,
): Promise<WitnessConfig> {
  const f = opts.fetchImpl ?? http();
  const base = opts.url.replace(/\/+$/, '');

  const keyRes = await f(`${base}/v1/pubkey`);
  if (!keyRes.ok) throw new Error(`witness /v1/pubkey returned ${keyRes.status}`);
  const keyBody = (await keyRes.json()) as { public_key_pem?: string };
  const pem = keyBody.public_key_pem;
  if (!pem?.includes('BEGIN PUBLIC KEY')) throw new Error('witness did not return an SPKI PEM');

  const logId = opts.logId ?? randomUUID();
  const regRes = await f(`${base}/v1/logs`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ log_id: logId, signing_pubkey: signingKey.public_key_pem }),
  });
  if (!regRes.ok) {
    throw new Error(`witness registration failed (${regRes.status}): ${await regRes.text()}`);
  }

  const cfg: WitnessConfig = {
    v: 1, url: base, log_id: logId, witness_pubkey_pem: pem,
    registered_at: new Date().toISOString(),
  };
  writeWitnessConfig(dir, cfg);
  return cfg;
}

export interface SubmitOutcome {
  ok: boolean;
  index: number;
  receipt?: WitnessReceipt;
  /** Present when the witness refused. */
  status?: number;
  error?: string;
  /** True when the refusal was a fork (409 with differing content). */
  conflict?: boolean;
}

export function receiptPath(dir: string, index: number): string {
  return join(dir, RECEIPTS_DIRNAME, `${String(index).padStart(8, '0')}.json`);
}

export function hasReceipt(dir: string, index: number): boolean {
  return existsSync(receiptPath(dir, index));
}

/** Submit one checkpoint. Never throws for an unreachable witness. */
export async function submitCheckpoint(
  dir: string,
  cfg: WitnessConfig,
  signingKey: SigningKeyFile,
  cp: SignedCheckpoint,
  fetchImpl?: FetchLike,
): Promise<SubmitOutcome> {
  const f = fetchImpl ?? http();
  const payload = submissionPayload(cfg.log_id, cp);
  const signature = signWithKey(signingKey, canonicalJson(payload));

  let res: Awaited<ReturnType<FetchLike>>;
  try {
    res = await f(`${cfg.url}/v1/logs/${cfg.log_id}/checkpoints`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        index: cp.index, seq_from: cp.seq_from, seq_to: cp.seq_to,
        merkle_root: cp.merkle_root, signature,
      }),
    });
  } catch (e) {
    return { ok: false, index: cp.index, error: `witness unreachable: ${(e as Error).message}` };
  }

  if (!res.ok) {
    const body = await res.text();
    return {
      ok: false, index: cp.index, status: res.status,
      error: `witness refused (${res.status}): ${body.slice(0, 300)}`,
      conflict: res.status === 409,
    };
  }

  const receipt = (await res.json()) as WitnessReceipt;
  // A receipt not signed by the pinned key is an attack, not a bad response.
  const verified = verifyWitnessSignature(cfg.witness_pubkey_pem, {
    log_id: receipt.log_id, index: receipt.index, seq_from: receipt.seq_from,
    seq_to: receipt.seq_to, merkle_root: receipt.merkle_root, witnessed_at: receipt.witnessed_at,
  }, receipt.witness_signature);
  if (!verified) throw new WitnessKeyMismatch(`receipt for index ${cp.index}`);

  mkdirSync(join(dir, RECEIPTS_DIRNAME), { recursive: true });
  writeFileSync(receiptPath(dir, cp.index), `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o644 });
  return { ok: true, index: cp.index, receipt };
}

export interface FetchedHead {
  reachable: boolean;
  error?: string;
  head?: WitnessHead;
  /** False when the head was not signed by the pinned key. */
  signatureValid?: boolean;
}

/** Fetch and authenticate the head. Never throws; verify decides what it means. */
export async function fetchHead(cfg: WitnessConfig, fetchImpl?: FetchLike): Promise<FetchedHead> {
  const f = fetchImpl ?? http();
  let res: Awaited<ReturnType<FetchLike>>;
  try {
    res = await f(`${cfg.url}/v1/logs/${cfg.log_id}/head`);
  } catch (e) {
    return { reachable: false, error: `witness unreachable: ${(e as Error).message}` };
  }
  if (!res.ok) return { reachable: false, error: `witness head returned ${res.status}` };

  let head: WitnessHead;
  try {
    head = (await res.json()) as WitnessHead;
  } catch (e) {
    return { reachable: false, error: `witness head was not JSON: ${(e as Error).message}` };
  }

  const { witness_signature, ...body } = head;
  const signatureValid = verifyWitnessSignature(
    cfg.witness_pubkey_pem, headSignedPayload(body as Omit<WitnessHead, 'witness_signature'>), witness_signature,
  );
  return { reachable: true, head, signatureValid };
}

/** Checkpoints with no stored receipt — the offline queue, derived from disk. */
export function pendingSubmissions(dir: string, checkpoints: readonly SignedCheckpoint[]): SignedCheckpoint[] {
  return checkpoints.filter((cp) => !hasReceipt(dir, cp.index));
}

/** What our local state says the witness should be holding. */
export interface ExpectedWitnessState {
  index: number;
  seq_to: number;
  merkle_root: string;
}

/**
 * The highest checkpoint we hold a receipt for, and its root.
 *
 * Receipts are signed by the witness, so this is not "what we think we sent"
 * but "what the witness confirmed receiving". That is the right thing to hold
 * a new witness to.
 */
export function expectedWitnessState(
  dir: string,
  checkpoints: readonly SignedCheckpoint[],
): ExpectedWitnessState | null {
  const witnessed = checkpoints.filter((cp) => hasReceipt(dir, cp.index));
  if (witnessed.length === 0) return null;
  const last = witnessed.reduce((a, b) => (b.index > a.index ? b : a));
  return { index: last.index, seq_to: last.seq_to, merkle_root: last.merkle_root };
}

export interface RepointRefusal {
  code:
    | 'not_registered'
    | 'same_url'
    | 'unreachable'
    | 'key_mismatch'
    | 'wrong_log'
    | 'no_record_of_log'
    | 'behind'
    | 'ahead'
    | 'root_mismatch';
  message: string;
}

export type RepointResult =
  | { ok: true; from: string; to: string; config: WitnessConfig; head: WitnessHead }
  | { ok: false; refusal: RepointRefusal };

/**
 * Move a registered log to a new witness hostname.
 *
 * The pinned key does NOT change. That is the whole point: a repoint is
 * "the same witness now answers somewhere else", and the way you prove it is
 * the same witness is that it can still sign with the key you pinned. If the
 * key differs this is a different witness, which is a re-registration and a
 * decision for a human — never something a repoint does quietly.
 *
 * The new URL must also already hold what the old one confirmed. A witness
 * that has never seen this log has no memory to offer, and one that disagrees
 * about a root it should be holding is not the same witness's data.
 */
export async function repointWitness(
  dir: string,
  newUrl: string,
  checkpoints: readonly SignedCheckpoint[],
  fetchImpl?: FetchLike,
): Promise<RepointResult> {
  const current = readWitnessConfig(dir);
  if (!current) {
    return { ok: false, refusal: { code: 'not_registered', message: 'this log has no witness registered; use `witness register`' } };
  }

  const to = newUrl.replace(/\/+$/, '');
  if (to === current.url) {
    return { ok: false, refusal: { code: 'same_url', message: `already pointed at ${to}` } };
  }

  // Probe the new URL with the EXISTING pinned key. fetchHead does the
  // signature check itself, against whatever key the config carries.
  const probe: WitnessConfig = { ...current, url: to };
  const fetched = await fetchHead(probe, fetchImpl);

  if (!fetched.reachable || !fetched.head) {
    return {
      ok: false,
      refusal: {
        code: fetched.error?.includes('404') ? 'no_record_of_log' : 'unreachable',
        message:
          `could not read a head for this log from ${to}: ${fetched.error ?? 'unknown error'}. ` +
          'Nothing was changed.',
      },
    };
  }

  if (fetched.signatureValid !== true) {
    return {
      ok: false,
      refusal: {
        code: 'key_mismatch',
        message:
          `${to} answered, but not with the key pinned when this log was registered. ` +
          'That is a different witness, not the same one at a new address. Re-pinning it here would ' +
          'defeat the pinning entirely, so it is refused. If you genuinely mean to move to a different ' +
          'witness, that is a new registration and a decision to make deliberately.',
      },
    };
  }

  const head = fetched.head;
  if (head.log_id !== current.log_id) {
    return {
      ok: false,
      refusal: { code: 'wrong_log', message: `${to} answered about log ${head.log_id}, not ${current.log_id}` },
    };
  }

  const expected = expectedWitnessState(dir, checkpoints);
  if (expected === null) {
    // Nothing has been witnessed yet, so there is no memory to preserve and
    // nothing to check against. Moving is harmless.
    const config: WitnessConfig = { ...current, url: to };
    writeWitnessConfig(dir, config);
    return { ok: true, from: current.url, to, config, head };
  }

  if (head.latest_index < expected.index) {
    return {
      ok: false,
      refusal: {
        code: 'behind',
        message:
          `${to} only holds up to checkpoint ${head.latest_index}, but ${current.url} confirmed ` +
          `checkpoint ${expected.index}. Moving would silently discard the witness's memory of ` +
          `${expected.index - head.latest_index} checkpoint(s) — exactly the deletion a witness exists to catch.`,
      },
    };
  }

  if (head.latest_index > expected.index) {
    return {
      ok: false,
      refusal: {
        code: 'ahead',
        message:
          `${to} holds checkpoint ${head.latest_index}, but the newest one we have a receipt for is ` +
          `${expected.index}. It has seen submissions this machine did not make, which means either ` +
          'another writer is using this log id or this is not the same log.',
      },
    };
  }

  if (head.merkle_root !== expected.merkle_root) {
    return {
      ok: false,
      refusal: {
        code: 'root_mismatch',
        message:
          `${to} records a different summary for checkpoint ${expected.index}: it has ` +
          `${head.merkle_root} where this log has ${expected.merkle_root}. Same index, different content ` +
          'is a fork.',
      },
    };
  }

  const config: WitnessConfig = { ...current, url: to };
  writeWitnessConfig(dir, config);
  return { ok: true, from: current.url, to, config, head };
}

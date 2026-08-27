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

/**
 * The witness this project runs, used when none is named.
 *
 * It is operated by Orisan. That is the point and also the limit: a witness is
 * only worth what its independence from the log's operator is worth, so ours
 * defends you against someone rewriting a log on their own machine, and does
 * NOT defend you against us. An auditor who needs to discount Orisan entirely
 * should be pointed at a witness we do not run — `--url` takes any of them, and
 * the key is pinned at registration whichever you choose.
 */
export const DEFAULT_WITNESS_URL = 'https://witness.orisan.org';

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
) => Promise<{
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
  text: () => Promise<string>;
  /** Optional so the many test doubles that predate Retry-After still satisfy this. */
  headers?: { get: (name: string) => string | null };
}>;

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
  /**
   * Issue #11 — the witness did not reject anything, it was busy or briefly
   * unavailable. Nothing is lost: unwitnessed checkpoints are re-derived from
   * disk as an offline queue and go out on the next run.
   *
   * Named `transient` rather than `throttled` because the retry class now
   * covers 502/503/504 as well as 429, and calling a bad gateway "throttled"
   * would be a lie in the one place an operator is reading for the truth.
   */
  transient?: boolean;
  /** How many requests were sent, including retries. */
  attempts?: number;
}

/**
 * Retry budget for a throttled submission.
 *
 * The defaults are deliberately small, because submitCheckpoint is awaited
 * while the recorder cuts a checkpoint: blocking an agent's recording for
 * thirty seconds to be polite to the witness is the wrong trade. Giving up is
 * safe — the checkpoint stays in the on-disk queue. The `witness submit`
 * command, which exists to drain that queue and is not in anyone's hot path,
 * passes a larger budget.
 */
export interface RetryBudget {
  maxAttempts?: number;
  maxTotalMs?: number;
  /** Injected by tests so a backoff does not actually sleep. */
  sleep?: (ms: number) => Promise<void>;
}

export const DEFAULT_RETRY: Required<Omit<RetryBudget, 'sleep'>> = { maxAttempts: 3, maxTotalMs: 5_000 };
export const DRAIN_RETRY: Required<Omit<RetryBudget, 'sleep'>> = { maxAttempts: 5, maxTotalMs: 30_000 };

/**
 * Statuses worth retrying, and why each is not a refusal.
 *
 *   429  the witness is rate-limiting this log; the submission was never read
 *   502  something in front of the witness could not reach it
 *   503  the witness is restarting or shedding load — a deploy looks like this
 *   504  the witness took too long, but may well have been fine
 *
 * None of these is an opinion about the checkpoint. Everything else is: a 409
 * is a fork, a 401 is a bad signature, a 400 is a malformed submission, and
 * retrying any of them just re-reports the same answer more slowly.
 */
export const RETRYABLE_STATUS: ReadonlySet<number> = new Set([429, 502, 503, 504]);

/** Base backoff before jitter: 400ms, 800ms, 1600ms … capped. */
const BACKOFF_BASE_MS = 400;
const BACKOFF_CAP_MS = 8_000;

/**
 * How long to wait before retrying, honouring Retry-After when the witness
 * sends one. RFC 9110 allows both a delay in seconds and an HTTP-date.
 */
export function retryDelayMs(attempt: number, retryAfter: string | null | undefined, jitter = Math.random()): number {
  if (retryAfter) {
    const seconds = Number(retryAfter.trim());
    if (Number.isFinite(seconds) && seconds >= 0) return Math.min(seconds * 1000, BACKOFF_CAP_MS);
    const when = Date.parse(retryAfter);
    if (!Number.isNaN(when)) return Math.min(Math.max(0, when - Date.now()), BACKOFF_CAP_MS);
    // An unparseable Retry-After is the server being odd, not a reason to
    // hammer it; fall through to the backoff.
  }
  const base = Math.min(BACKOFF_BASE_MS * 2 ** attempt, BACKOFF_CAP_MS);
  // Jitter so several recorders throttled at once do not retry in lockstep.
  return Math.round(base * (0.5 + jitter * 0.5));
}

export function receiptPath(dir: string, index: number): string {
  return join(dir, RECEIPTS_DIRNAME, `${String(index).padStart(8, '0')}.json`);
}

export function hasReceipt(dir: string, index: number): boolean {
  return existsSync(receiptPath(dir, index));
}

/**
 * Submit one checkpoint. Never throws for an unreachable witness.
 *
 * A 429 is a request to slow down, NOT a rejection of the submission, and this
 * used to report it as `witness refused (429)` — which reads to an operator
 * like the witness objected to the content. It now backs off and retries, and
 * if the budget runs out says it was throttled and will go out on the next run.
 */
export async function submitCheckpoint(
  dir: string,
  cfg: WitnessConfig,
  signingKey: SigningKeyFile,
  cp: SignedCheckpoint,
  fetchImpl?: FetchLike,
  retry: RetryBudget = {},
): Promise<SubmitOutcome> {
  const f = fetchImpl ?? http();
  const payload = submissionPayload(cfg.log_id, cp);
  const signature = signWithKey(signingKey, canonicalJson(payload));

  const maxAttempts = retry.maxAttempts ?? DEFAULT_RETRY.maxAttempts;
  const maxTotalMs = retry.maxTotalMs ?? DEFAULT_RETRY.maxTotalMs;
  const sleep = retry.sleep ?? ((ms: number) => new Promise<void>((r) => { setTimeout(r, ms); }));

  let res: Awaited<ReturnType<FetchLike>>;
  let attempts = 0;
  let spentMs = 0;
  let lastRetryAfter: string | null = null;

  for (;;) {
    attempts++;
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
      return { ok: false, index: cp.index, attempts, error: `witness unreachable: ${(e as Error).message}` };
    }

    if (!RETRYABLE_STATUS.has(res.status)) break;
    const status = res.status;

    // Drain the body so the connection can be reused, and keep the header.
    // 503 carries Retry-After as legitimately as 429 does.
    await res.text().catch(() => '');
    lastRetryAfter = res.headers?.get('retry-after') ?? null;

    const wait = retryDelayMs(attempts - 1, lastRetryAfter);
    if (attempts >= maxAttempts || spentMs + wait > maxTotalMs) {
      const what = status === 429
        ? `witness throttled this log (429)${lastRetryAfter ? `, asking for ${lastRetryAfter}s` : ''}`
        : `witness temporarily unavailable (${status})`;
      return {
        ok: false, index: cp.index, status, attempts, transient: true,
        error: `${what} after ${attempts} attempt(s); `
          + 'the checkpoint stays queued and goes out on the next run',
      };
    }
    await sleep(wait);
    spentMs += wait;
  }

  if (!res.ok) {
    const body = await res.text();
    return {
      ok: false, index: cp.index, status: res.status, attempts,
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
  return { ok: true, index: cp.index, receipt, attempts };
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

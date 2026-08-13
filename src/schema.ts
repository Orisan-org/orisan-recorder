/**
 * R1.1 — versioned event schema and chain hashing.
 *
 * The chain here detects careless edits: flip a byte, drop a record, reorder
 * two, and verification breaks at a named seq. It does NOT detect a competent
 * rewrite, because every input to the hash is public — an attacker who can
 * write the store can recompute the whole chain from genesis with the function
 * below and produce a log that verifies clean. That hole is closed by the
 * signed, externally anchored checkpoints in R1.3, not here. Nothing in this
 * module should be described as tamper-proof.
 */

import { createHash, randomUUID } from 'node:crypto';

/**
 * Bumped whenever the hashed shape of an event changes. Part of the hash input.
 *
 * v3 adds session_id. Note this skips v2 for events: the checkpoint body is
 * independently at v2, and leaving a v2 in both namespaces meaning different
 * things is the kind of ambiguity that costs an hour in an incident. Nothing
 * migrates — v1 logs will not validate, which is correct, because their events
 * genuinely lack a field the current shape requires.
 */
export const SCHEMA_VERSION = 3 as const;

/** prev_hash of the first event in a chain. */
export const GENESIS_PREV_HASH = '0'.repeat(64);

export const EVENT_KINDS = [
  'model_call',
  'tool_call',
  'config_change',
  'flag',
  'redaction',
] as const;

export type EventKind = (typeof EVENT_KINDS)[number];

/**
 * Where `ts` came from. Recorded because a wall clock is attacker-influenced and
 * an auditor is entitled to know we are quoting the host, not a time authority.
 * Trusted time arrives with the RFC 3161 anchor in R1.3.
 */
export const CLOCK_SOURCES = ['host_wall_clock'] as const;
export type ClockSource = (typeof CLOCK_SOURCES)[number];

export interface Actor {
  /** The person on whose behalf the action ran, if known. */
  human: string | null;
  /** SPIFFE-style workload id, e.g. spiffe://orisan/agent/claude-code. */
  agent_id: string;
  /** The tool surface that acted, e.g. "claude-code", "cursor". */
  tool: string | null;
}

/** An event as it is hashed and written. `hash` is excluded from its own input. */
export interface RecordedEvent {
  v: typeof SCHEMA_VERSION;
  seq: number;
  event_id: string;
  /**
   * The recording session this event belongs to. One recorder process — one
   * shim wrapping one MCP server, one demo run — is one session.
   *
   * Inside the hash like every other field, so events cannot be moved between
   * sessions after the fact. Grouping evidence by "which run was this?" is
   * only worth anything if the grouping is itself sealed.
   */
  session_id: string;
  ts: string;
  clock_source: ClockSource;
  actor: Actor;
  kind: EventKind;
  target: string | null;
  /** sha256 of the canonical arguments. The arguments themselves are never inlined. */
  args_digest: string | null;
  /** Opaque handle into the encrypted payload store, or null. */
  payload_ref: string | null;
  outcome: string | null;
  duration_ms: number | null;
  prev_hash: string;
  hash: string;
}

/** Everything the caller supplies; the store owns seq, chaining and hashing. */
export type EventInput = Omit<
  RecordedEvent,
  'v' | 'seq' | 'event_id' | 'ts' | 'clock_source' | 'session_id' | 'prev_hash' | 'hash'
> & {
  event_id?: string;
  ts?: string;
};

/**
 * RFC 8785-style canonical JSON: object keys sorted, no incidental whitespace.
 * Two structurally equal values must produce byte-identical output on every
 * platform, or the chain is not portable.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    const src = value as Record<string, unknown>;
    // Object.create(null), not {}. With a normal object literal, assigning the
    // key "__proto__" hits Object.prototype's setter: no own property is
    // created and the key VANISHES from the canonical string. JSON.parse makes
    // __proto__ a real own property, so it survives in the file — meaning
    // {"a":1} and {"a":1,"__proto__":{...}} hashed identically and arbitrary
    // content could be parked inside an anchored event, uncommitted by the
    // chain hash, the Merkle root, the signature and the timestamp.
    // A null-prototype target has no such setter, so the key is data.
    const out = Object.create(null) as Record<string, unknown>;
    for (const k of Object.keys(src).sort()) out[k] = sortKeys(src[k]);
    return out;
  }
  return value;
}

/**
 * Join parts with NUL separators before hashing.
 *
 * Plain concatenation is ambiguous: ("ab","c") and ("a","bc") hash identically,
 * which lets an attacker shift a byte across a field boundary without changing
 * the digest. NUL cannot occur in canonical JSON output or in a hex digest, so
 * it is a safe separator that makes the parts unambiguous.
 */
export function hashParts(parts: readonly string[]): string {
  for (const p of parts) {
    if (p.includes('\0')) throw new Error('hash part contains a NUL separator');
  }
  return createHash('sha256').update(parts.join('\0'), 'utf8').digest('hex');
}

/**
 * The chain hash of an event: canonical JSON of every field except `hash`,
 * then the previous hash, NUL-separated, under a versioned domain tag.
 */
export function computeEventHash(event: Omit<RecordedEvent, 'hash'>): string {
  const { hash: _omit, ...rest } = event as RecordedEvent;
  void _omit;
  return hashParts([
    `orisan-recorder/event/v${SCHEMA_VERSION}`,
    canonicalJson(rest),
    event.prev_hash,
  ]);
}

/** sha256 over canonical JSON of a tool's arguments. */
export function argsDigest(args: unknown): string {
  return createHash('sha256').update(canonicalJson(args), 'utf8').digest('hex');
}

/**
 * Seal an input into a fully-formed event on the end of a chain.
 *
 * session_id is stamped by the store rather than supplied per event, the same
 * way clock_source is: it is a property of the recorder that produced the
 * event, not of the individual call, and letting callers pass it per event
 * would let one session's events claim to be another's.
 */
export function buildEvent(
  input: EventInput,
  seq: number,
  prevHash: string,
  sessionId: string,
): RecordedEvent {
  const base: Omit<RecordedEvent, 'hash'> = {
    v: SCHEMA_VERSION,
    seq,
    event_id: input.event_id ?? randomUUID(),
    session_id: sessionId,
    ts: input.ts ?? new Date().toISOString(),
    clock_source: 'host_wall_clock',
    actor: input.actor,
    kind: input.kind,
    target: input.target,
    args_digest: input.args_digest,
    payload_ref: input.payload_ref,
    outcome: input.outcome,
    duration_ms: input.duration_ms,
    prev_hash: prevHash,
  };
  return { ...base, hash: computeEventHash(base) };
}

const HEX64 = /^[0-9a-f]{64}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Exactly the keys a v1 event may carry. Anything else is rejected. */
const ALLOWED_EVENT_KEYS: ReadonlySet<string> = new Set([
  'v', 'seq', 'event_id', 'session_id', 'ts', 'clock_source', 'actor', 'kind',
  'target', 'args_digest', 'payload_ref', 'outcome', 'duration_ms', 'prev_hash', 'hash',
]);

const ALLOWED_ACTOR_KEYS: ReadonlySet<string> = new Set(['human', 'agent_id', 'tool']);

/** Structural validation. Wrong shape is a different failure from a broken chain. */
export function validateEvent(value: unknown): asserts value is RecordedEvent {
  const e = value as Partial<RecordedEvent> | null;
  if (!e || typeof e !== 'object') throw new Error('event is not an object');
  if (e.v !== SCHEMA_VERSION) throw new Error(`unsupported schema version: ${String(e.v)}`);
  if (!Number.isSafeInteger(e.seq) || (e.seq as number) < 0) throw new Error('seq must be a non-negative integer');
  if (typeof e.event_id !== 'string' || e.event_id.length === 0) throw new Error('event_id must be a non-empty string');
  if (typeof e.session_id !== 'string' || !UUID_RE.test(e.session_id)) throw new Error('session_id must be a uuid');
  if (typeof e.ts !== 'string' || Number.isNaN(Date.parse(e.ts))) throw new Error('ts must be an ISO timestamp');
  if (!CLOCK_SOURCES.includes(e.clock_source as ClockSource)) throw new Error('unknown clock_source');
  if (!EVENT_KINDS.includes(e.kind as EventKind)) throw new Error(`unknown kind: ${String(e.kind)}`);
  // Unknown keys are rejected outright. An event that carries a field the hash
  // does not cover is a field an attacker can edit freely afterwards; there is
  // no benign reason for one to exist.
  for (const k of Object.keys(e as object)) {
    if (!ALLOWED_EVENT_KEYS.has(k)) throw new Error(`unknown event field: ${k}`);
  }
  const a = e.actor as Actor | undefined;
  if (!a || typeof a !== 'object') throw new Error('actor must be an object');
  for (const k of Object.keys(a)) {
    if (!ALLOWED_ACTOR_KEYS.has(k)) throw new Error(`unknown actor field: ${k}`);
  }
  if (typeof a.agent_id !== 'string' || a.agent_id.length === 0) throw new Error('actor.agent_id must be a non-empty string');
  if (a.human !== null && typeof a.human !== 'string') throw new Error('actor.human must be a string or null');
  if (a.tool !== null && typeof a.tool !== 'string') throw new Error('actor.tool must be a string or null');
  if (e.target !== null && typeof e.target !== 'string') throw new Error('target must be a string or null');
  if (e.outcome !== null && typeof e.outcome !== 'string') throw new Error('outcome must be a string or null');
  if (e.payload_ref !== null && !HEX64.test(String(e.payload_ref))) throw new Error('payload_ref must be sha256 hex or null');
  if (e.args_digest !== null && !HEX64.test(String(e.args_digest))) throw new Error('args_digest must be sha256 hex or null');
  if (e.duration_ms !== null && !Number.isFinite(e.duration_ms as number)) throw new Error('duration_ms must be a number or null');
  if (!HEX64.test(String(e.prev_hash))) throw new Error('prev_hash must be sha256 hex');
  if (!HEX64.test(String(e.hash))) throw new Error('hash must be sha256 hex');
}

export interface ChainBreak {
  seq: number;
  event_id: string;
  reason: 'hash_mismatch' | 'prev_hash_mismatch' | 'seq_gap';
  expected: string;
  actual: string;
}

/**
 * Walk a chain from genesis and report every break, each naming its seq.
 *
 * Reports ALL breaks rather than stopping at the first: an operator who edited
 * one record usually edited more, and a verifier that quits early understates
 * the damage. Note again what this cannot do — a chain recomputed end to end
 * passes here. R1.4 catches that by comparing against an anchored checkpoint.
 */
export function verifyChain(
  events: readonly RecordedEvent[],
  startPrevHash: string = GENESIS_PREV_HASH,
  expectedFirstSeq = 0,
): ChainBreak[] {
  const breaks: ChainBreak[] = [];
  let prev = startPrevHash;
  let expectedSeq = expectedFirstSeq;

  for (const e of events) {
    if (e.seq !== expectedSeq) {
      breaks.push({
        seq: e.seq,
        event_id: e.event_id,
        reason: 'seq_gap',
        expected: String(expectedSeq),
        actual: String(e.seq),
      });
      expectedSeq = e.seq;
    }
    if (e.prev_hash !== prev) {
      breaks.push({
        seq: e.seq,
        event_id: e.event_id,
        reason: 'prev_hash_mismatch',
        expected: prev,
        actual: e.prev_hash,
      });
    }
    const recomputed = computeEventHash(e);
    if (recomputed !== e.hash) {
      breaks.push({
        seq: e.seq,
        event_id: e.event_id,
        reason: 'hash_mismatch',
        expected: recomputed,
        actual: e.hash,
      });
    }
    // Continue from the STORED hash so one edited record does not cascade into
    // a false report against every record after it. The break is named once,
    // at the seq where it happened.
    prev = e.hash;
    expectedSeq = e.seq + 1;
  }
  return breaks;
}

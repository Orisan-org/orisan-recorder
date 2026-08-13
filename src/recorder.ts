/**
 * Recorder — the store plus the checkpoint cadence from R1.3.
 *
 * Cuts a checkpoint every N events (default 500) and on session end, then
 * tries to anchor it. Anchoring failure never blocks recording; the checkpoint
 * stays queued and `orisan-rec anchor` drains it later.
 */

import { DEFAULT_CHECKPOINT_INTERVAL, appendCheckpoint, buildCheckpoint, generateSigningKey, loadSigningKey, readCheckpoints, type SignedCheckpoint, type SigningKeyFile } from './checkpoint.js';
import { EventStore, type StoreOptions } from './store.js';
import { anchorCheckpoint, type AnchorOptions } from './tsa.js';
import { witnessCheckpoint } from './witness.js';
import { readWitnessConfig, submitCheckpoint, type WitnessConfig } from './witness-service.js';
import type { EventInput, RecordedEvent } from './schema.js';
import { existsSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { PUBLIC_KEY_FILENAME } from './checkpoint.js';

export interface RecorderOptions extends StoreOptions {
  checkpointInterval?: number;
  anchor?: AnchorOptions & { enabled?: boolean };
  /**
   * Path to the external witness log. Should live OUTSIDE the log directory —
   * ideally on a machine or account the recorder's operator cannot rewrite.
   * Without it, tail truncation is undetectable and verify cannot return clean.
   */
  witnessFile?: string;
  /** Set false to skip witness submission (used by offline-only commands). */
  submitToWitness?: boolean;
  /** Session id for every event this recorder appends. Defaults to a fresh uuid. */
  sessionId?: string;
  /**
   * Where the signing private key lives. Defaults to ~/.orisan/signing.key —
   * deliberately NOT the log directory, because a key stored beside the data
   * it authenticates lets anyone who can rewrite the log re-sign it.
   */
  signingKeyPath?: string;
}

/** Default key location: outside any log directory. */
export function defaultSigningKeyPath(): string {
  return join(homedir(), '.orisan', 'signing.key');
}

export class Recorder {
  readonly dir: string;
  private readonly store: EventStore;
  private readonly key: SigningKeyFile;
  private readonly interval: number;
  private readonly anchorOpts: AnchorOptions & { enabled: boolean };
  private readonly witnessFile: string | undefined;
  private readonly witnessService: WitnessConfig | null;
  /** seq of the last event already covered by a checkpoint. */
  private lastCheckpointedSeq: number;
  /** The tail of the checkpoint chain, so the next one can link to it. */
  private lastCheckpoint: SignedCheckpoint | null;

  private constructor(dir: string, store: EventStore, key: SigningKeyFile, opts: RecorderOptions) {
    this.dir = dir;
    this.store = store;
    this.key = key;
    this.interval = opts.checkpointInterval ?? DEFAULT_CHECKPOINT_INTERVAL;
    if (this.interval < 1) throw new Error('checkpointInterval must be >= 1');
    this.anchorOpts = { enabled: true, ...(opts.anchor ?? {}) };
    this.witnessFile = opts.witnessFile;
    // Present only if `orisan-rec witness register` has run for this log.
    this.witnessService = opts.submitToWitness === false ? null : readWitnessConfig(dir);

    const cps = readCheckpoints(dir);
    this.lastCheckpoint = cps.length ? cps[cps.length - 1]! : null;
    this.lastCheckpointedSeq = this.lastCheckpoint ? this.lastCheckpoint.seq_to : -1;
  }

  static open(dir: string, opts: RecorderOptions = {}): Recorder {
    const { store } = EventStore.open(dir, opts);
    const keyPath = opts.signingKeyPath ?? defaultSigningKeyPath();
    const key = existsSync(keyPath) ? loadSigningKey(dir, keyPath) : generateSigningKey(dir, keyPath);
    // The public key must exist in the LOG directory even when the private key
    // was loaded from elsewhere — otherwise a log signed with a pre-existing
    // key ships with nothing to verify it against.
    const pubPath = join(dir, PUBLIC_KEY_FILENAME);
    if (!existsSync(pubPath)) writeFileSync(pubPath, key.public_key_pem, { mode: 0o644 });
    return new Recorder(dir, store, key, opts);
  }

  get eventCount(): number {
    return this.store.count;
  }

  /** The session every event from this recorder carries. */
  get sessionId(): string {
    return this.store.session;
  }

  /** Append an event; cut a checkpoint if the cadence says so. */
  async record(input: EventInput): Promise<RecordedEvent> {
    const e = this.store.append(input);
    const pending = e.seq - this.lastCheckpointedSeq;
    if (pending >= this.interval) await this.cutCheckpoint('interval');
    return e;
  }

  /** Force a checkpoint over everything not yet covered. No-op if nothing is pending. */
  async cutCheckpoint(reason: 'interval' | 'session_end' | 'manual'): Promise<SignedCheckpoint | null> {
    const from = this.lastCheckpointedSeq + 1;
    const events = this.store.readAll().filter((e) => e.seq >= from);
    if (events.length === 0) return null;

    const cp = buildCheckpoint(events.map((e) => e.hash), from, reason, this.key, this.lastCheckpoint);
    appendCheckpoint(this.dir, cp);
    this.lastCheckpoint = cp;
    this.lastCheckpointedSeq = cp.seq_to;

    // Witness before anchoring: the witness is the record that this checkpoint
    // existed at all, and it must not be lost if the TSA call hangs or fails.
    if (this.witnessFile !== undefined) witnessCheckpoint(this.witnessFile, cp);

    if (this.anchorOpts.enabled) {
      // Deliberately ignoring the result: an unreachable TSA must never stop
      // recording. The gap shows up as an unanchored checkpoint at verify time.
      await anchorCheckpoint(this.dir, cp, this.anchorOpts);
    }

    if (this.witnessService) {
      // Same posture as the TSA: an unreachable witness must not stop
      // recording. A missing receipt leaves the checkpoint queued, and verify
      // reports it as not-yet-witnessed rather than as tampering. A key
      // mismatch is different — that throws, and is meant to.
      try {
        await submitCheckpoint(this.dir, this.witnessService, this.key, cp);
      } catch (e) {
        if ((e as Error).name === 'WitnessKeyMismatch') throw e;
      }
    }
    return cp;
  }

  /** Cut a final checkpoint and close. */
  async end(): Promise<SignedCheckpoint | null> {
    const cp = await this.cutCheckpoint('session_end');
    this.store.close();
    return cp;
  }

  close(): void {
    this.store.close();
  }
}

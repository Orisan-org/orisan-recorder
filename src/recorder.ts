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
import type { EventInput, RecordedEvent } from './schema.js';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { SIGNING_KEY_FILENAME } from './checkpoint.js';

export interface RecorderOptions extends StoreOptions {
  checkpointInterval?: number;
  anchor?: AnchorOptions & { enabled?: boolean };
}

export class Recorder {
  readonly dir: string;
  private readonly store: EventStore;
  private readonly key: SigningKeyFile;
  private readonly interval: number;
  private readonly anchorOpts: AnchorOptions & { enabled: boolean };
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

    const cps = readCheckpoints(dir);
    this.lastCheckpoint = cps.length ? cps[cps.length - 1]! : null;
    this.lastCheckpointedSeq = this.lastCheckpoint ? this.lastCheckpoint.seq_to : -1;
  }

  static open(dir: string, opts: RecorderOptions = {}): Recorder {
    const { store } = EventStore.open(dir, opts);
    const key = existsSync(join(dir, SIGNING_KEY_FILENAME)) ? loadSigningKey(dir) : generateSigningKey(dir);
    return new Recorder(dir, store, key, opts);
  }

  get eventCount(): number {
    return this.store.count;
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

    if (this.anchorOpts.enabled) {
      // Deliberately ignoring the result: an unreachable TSA must never stop
      // recording. The gap shows up as an unanchored checkpoint at verify time.
      await anchorCheckpoint(this.dir, cp, this.anchorOpts);
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

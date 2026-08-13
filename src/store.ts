/**
 * R1.2 — append-only event store.
 *
 * The JSONL segments are the truth. Everything else in this repo (the SQLite
 * index, the UI, exports) is a cache that must be rebuildable from them.
 *
 * Durability contract: append() returns only after the line is on disk. One
 * write(2) per event followed by fsync. A process killed mid-write can
 * therefore lose at most the final line, and open() truncates that partial
 * tail and reports it rather than letting a half-written record sit in the
 * middle of a chain.
 */

import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  statSync,
  truncateSync,
  writeSync,
} from 'node:fs';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';

import {
  GENESIS_PREV_HASH,
  buildEvent,
  validateEvent,
  verifyChain,
  type ChainBreak,
  type EventInput,
  type RecordedEvent,
} from './schema.js';

// Exactly four digits. `\d{4,}` let events-0000 and events-00000 both index 0,
// so the order of the truth store depended on readdirSync order.
const SEGMENT_RE = /^events-(\d{4})\.jsonl$/;

export interface StoreOptions {
  /**
   * Session this store's appends belong to. One store instance is one session;
   * defaults to a fresh uuid so a session id always exists rather than being
   * optional and therefore sometimes absent.
   */
  sessionId?: string;
  /**
   * Never create, never truncate. verify() uses this: a verifier that writes
   * to the artefact it is checking destroys evidence — a torn tail removed by
   * the first run is invisible to the second — and creating a missing
   * directory turns "that path does not exist" into a confusing exit 2.
   */
  readOnly?: boolean;
  /** Roll to a new segment after this many events. */
  maxEventsPerSegment?: number;
  /**
   * fsync after every append. Default true and that is the supported setting;
   * false exists so tests that write tens of thousands of events stay quick.
   * Turning it off trades the durability contract above for speed.
   */
  fsync?: boolean;
}

export interface RecoveryReport {
  /** A partial trailing line was found and removed. */
  truncatedPartialTail: boolean;
  /** Bytes discarded from the tail. */
  bytesDiscarded: number;
  /** Segment the truncation happened in, if any. */
  segment: string | null;
}

export function segmentName(index: number): string {
  return `events-${String(index).padStart(4, '0')}.jsonl`;
}

export function listSegments(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => SEGMENT_RE.test(f))
    .sort((a, b) => segmentIndex(a) - segmentIndex(b));
}

export function segmentIndex(name: string): number {
  const m = SEGMENT_RE.exec(name);
  if (!m) throw new Error(`not a segment file: ${name}`);
  return Number.parseInt(m[1]!, 10);
}

/**
 * Split a segment's bytes into complete lines plus any trailing remainder.
 * A "complete" line is one terminated by \n; anything after the last \n is a
 * torn write.
 */
function splitLines(buf: Buffer): { lines: string[]; remainder: Buffer } {
  const text = buf.toString('utf8');
  const lastNl = text.lastIndexOf('\n');
  if (lastNl === -1) return { lines: [], remainder: buf };
  const complete = text.slice(0, lastNl);
  const remainder = Buffer.from(text.slice(lastNl + 1), 'utf8');
  const lines = complete.length === 0 ? [] : complete.split('\n');
  return { lines, remainder };
}

/**
 * The seq of the last event, read from the tail of the last segment.
 *
 * Exists so a cache can be checked for staleness without reading the whole
 * log — which is the thing the cache is there to avoid. Returns -1 for an
 * empty or absent log.
 */
export function peekHeadSeq(dir: string): number {
  const segments = listSegments(dir);
  if (segments.length === 0) return -1;
  const last = segments[segments.length - 1]!;
  const { lines } = splitLines(readFileSync(join(dir, last)));
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i]!;
    if (line.length === 0) continue;
    try {
      const seq = (JSON.parse(line) as { seq?: unknown }).seq;
      if (typeof seq === 'number') return seq;
    } catch {
      // A torn tail is the recovery path's problem, not this probe's.
    }
  }
  return -1;
}

export class EventStore {
  readonly dir: string;
  private readonly maxEventsPerSegment: number;
  private readonly doFsync: boolean;
  private readonly readOnly: boolean;
  private readonly sessionId: string;

  private fd: number | null = null;
  private currentSegment = 0;
  private eventsInCurrentSegment = 0;
  private nextSeq = 0;
  private lastHash: string = GENESIS_PREV_HASH;

  private constructor(dir: string, opts: Required<StoreOptions>) {
    this.dir = dir;
    this.maxEventsPerSegment = opts.maxEventsPerSegment;
    this.doFsync = opts.fsync;
    this.readOnly = opts.readOnly;
    this.sessionId = opts.sessionId;
  }

  /**
   * Open (creating if needed), recover any torn tail, and position at the end
   * of the chain. Safe to call on a directory a killed process left behind.
   */
  static open(dir: string, opts: StoreOptions = {}): { store: EventStore; recovery: RecoveryReport } {
    const resolved: Required<StoreOptions> = {
      maxEventsPerSegment: opts.maxEventsPerSegment ?? 1000,
      fsync: opts.fsync ?? true,
      readOnly: opts.readOnly ?? false,
      sessionId: opts.sessionId ?? randomUUID(),
    };
    if (resolved.maxEventsPerSegment < 1) throw new Error('maxEventsPerSegment must be >= 1');

    if (resolved.readOnly) {
      if (!existsSync(dir)) throw new Error(`no such log directory: ${dir}`);
    } else {
      mkdirSync(dir, { recursive: true });
    }
    const store = new EventStore(dir, resolved);
    const recovery = store.recover();
    return { store, recovery };
  }

  private recover(): RecoveryReport {
    const report: RecoveryReport = { truncatedPartialTail: false, bytesDiscarded: 0, segment: null };
    const segments = listSegments(this.dir);

    if (segments.length === 0) {
      this.currentSegment = 0;
      this.eventsInCurrentSegment = 0;
      this.nextSeq = 0;
      this.lastHash = GENESIS_PREV_HASH;
      return report;
    }

    let count = 0;
    let last: RecordedEvent | null = null;

    for (let i = 0; i < segments.length; i++) {
      const name = segments[i]!;
      const path = join(this.dir, name);
      const { lines, remainder } = splitLines(readFileSync(path));
      const isLastSegment = i === segments.length - 1;

      if (remainder.length > 0) {
        if (this.readOnly) {
          // Report it; do not repair it. The caller decides what a torn tail means.
          report.truncatedPartialTail = true;
          report.bytesDiscarded = remainder.length;
          report.segment = name;
        } else if (!isLastSegment) {
          // A torn line anywhere but the very end is real corruption, not a
          // crash artefact. Refuse rather than silently dropping a record.
          throw new Error(`corrupt segment ${name}: incomplete line before end of chain`);
        } else {
          truncateSync(path, statSync(path).size - remainder.length);
          report.truncatedPartialTail = true;
          report.bytesDiscarded = remainder.length;
          report.segment = name;
        }
      }

      let inThisSegment = 0;
      for (const line of lines) {
        if (line.length === 0) continue;
        const parsed = JSON.parse(line) as unknown;
        validateEvent(parsed);
        last = parsed;
        count++;
        inThisSegment++;
      }

      if (isLastSegment) {
        this.currentSegment = segmentIndex(name);
        this.eventsInCurrentSegment = inThisSegment;
      }
    }

    this.nextSeq = last ? last.seq + 1 : 0;
    this.lastHash = last ? last.hash : GENESIS_PREV_HASH;
    void count;
    return report;
  }

  private ensureOpenSegment(): number {
    if (this.eventsInCurrentSegment >= this.maxEventsPerSegment) {
      if (this.fd !== null) {
        closeSync(this.fd);
        this.fd = null;
      }
      this.currentSegment++;
      this.eventsInCurrentSegment = 0;
    }
    if (this.fd === null) {
      this.fd = openSync(join(this.dir, segmentName(this.currentSegment)), 'a');
    }
    return this.fd;
  }

  /** Append one event. Returns once the line is durable on disk. */
  append(input: EventInput): RecordedEvent {
    if (this.readOnly) throw new Error('store was opened read-only');
    const event = buildEvent(input, this.nextSeq, this.lastHash, this.sessionId);
    const fd = this.ensureOpenSegment();
    const line = Buffer.from(`${JSON.stringify(event)}\n`, 'utf8');

    // Single write so a crash can only ever tear the tail, never interleave.
    let written = 0;
    while (written < line.length) {
      written += writeSync(fd, line, written, line.length - written);
    }
    if (this.doFsync) fsyncSync(fd);

    this.nextSeq = event.seq + 1;
    this.lastHash = event.hash;
    this.eventsInCurrentSegment++;
    return event;
  }

  /** Stream every event in chain order across all segments. */
  *read(): Generator<RecordedEvent> {
    for (const name of listSegments(this.dir)) {
      const { lines } = splitLines(readFileSync(join(this.dir, name)));
      for (const line of lines) {
        if (line.length === 0) continue;
        const parsed = JSON.parse(line) as unknown;
        validateEvent(parsed);
        yield parsed;
      }
    }
  }

  readAll(): RecordedEvent[] {
    return [...this.read()];
  }

  /**
   * Chain-level integrity only. This is NOT the R1.4 verify command: it cannot
   * see a chain that was recomputed from genesis, which is precisely why R1.4
   * has to compare against an externally anchored checkpoint.
   */
  verifyChainOnly(): ChainBreak[] {
    return verifyChain(this.readAll());
  }

  /** The session id stamped on this store's appends. */
  get session(): string { return this.sessionId; }

  get head(): { seq: number; hash: string } {
    return { seq: this.nextSeq - 1, hash: this.lastHash };
  }

  get count(): number {
    return this.nextSeq;
  }

  close(): void {
    if (this.fd !== null) {
      closeSync(this.fd);
      this.fd = null;
    }
  }
}

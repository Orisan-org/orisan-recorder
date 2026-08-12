/**
 * R1.2 — SQLite index over the event log.
 *
 * This is a CACHE. The JSONL segments are the truth. Nothing here may be the
 * only copy of anything, and every query answerable from the index must be
 * answerable (more slowly) by scanning the segments. If the two ever disagree,
 * the index is wrong by definition — rebuild() exists for exactly that, and
 * the UI is expected to call it rather than trying to repair rows.
 *
 * Deliberately NOT stored here: prev_hash and hash. Verification must never be
 * able to read its evidence from a mutable derived cache; it reads the
 * segments. Storing the chain here would create a second place to lie.
 */

import Database from 'better-sqlite3';
import { join } from 'node:path';

import type { RecordedEvent } from './schema.js';
import { EventStore } from './store.js';

export const INDEX_FILENAME = 'index.sqlite';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS events (
  seq            INTEGER PRIMARY KEY,
  event_id       TEXT    NOT NULL,
  ts             TEXT    NOT NULL,
  kind           TEXT    NOT NULL,
  actor_human    TEXT,
  actor_agent_id TEXT    NOT NULL,
  actor_tool     TEXT,
  target         TEXT,
  outcome        TEXT,
  duration_ms    INTEGER,
  payload_ref    TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_kind     ON events(kind);
CREATE INDEX IF NOT EXISTS idx_events_agent    ON events(actor_agent_id);
CREATE INDEX IF NOT EXISTS idx_events_kind_ts  ON events(kind, ts);

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`;

export interface EventQuery {
  kind?: RecordedEvent['kind'];
  agentId?: string;
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
}

/** A row as the UI wants it. Chain fields are absent on purpose — see header. */
export interface IndexedEvent {
  seq: number;
  event_id: string;
  ts: string;
  kind: string;
  actor_human: string | null;
  actor_agent_id: string;
  actor_tool: string | null;
  target: string | null;
  outcome: string | null;
  duration_ms: number | null;
  payload_ref: string | null;
}

export class EventIndex {
  private readonly db: Database.Database;

  private constructor(db: Database.Database) {
    this.db = db;
    this.db.pragma('journal_mode = WAL');
    this.db.exec(SCHEMA);
  }

  static open(dir: string): EventIndex {
    return new EventIndex(new Database(join(dir, INDEX_FILENAME)));
  }

  /** In-memory index, for tests and for read-only consumers of a bundle. */
  static memory(): EventIndex {
    return new EventIndex(new Database(':memory:'));
  }

  private insertStmt() {
    return this.db.prepare(`
      INSERT OR REPLACE INTO events
        (seq, event_id, ts, kind, actor_human, actor_agent_id, actor_tool, target, outcome, duration_ms, payload_ref)
      VALUES
        (@seq, @event_id, @ts, @kind, @actor_human, @actor_agent_id, @actor_tool, @target, @outcome, @duration_ms, @payload_ref)
    `);
  }

  private static row(e: RecordedEvent) {
    return {
      seq: e.seq,
      event_id: e.event_id,
      ts: e.ts,
      kind: e.kind,
      actor_human: e.actor.human,
      actor_agent_id: e.actor.agent_id,
      actor_tool: e.actor.tool,
      target: e.target,
      outcome: e.outcome,
      duration_ms: e.duration_ms,
      payload_ref: e.payload_ref,
    };
  }

  put(event: RecordedEvent): void {
    this.insertStmt().run(EventIndex.row(event));
  }

  putMany(events: Iterable<RecordedEvent>): number {
    const stmt = this.insertStmt();
    let n = 0;
    this.db.transaction(() => {
      for (const e of events) {
        stmt.run(EventIndex.row(e));
        n++;
      }
    })();
    return n;
  }

  /**
   * Drop every row and refill from the segments. The only supported repair.
   * Returns the number of events indexed.
   */
  rebuild(store: EventStore): number {
    this.db.exec('DELETE FROM events');
    const n = this.putMany(store.read());
    this.db
      .prepare('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)')
      .run('rebuilt_at', new Date().toISOString());
    return n;
  }

  query(q: EventQuery = {}): IndexedEvent[] {
    const where: string[] = [];
    const params: Record<string, unknown> = {};
    if (q.kind !== undefined) { where.push('kind = @kind'); params['kind'] = q.kind; }
    if (q.agentId !== undefined) { where.push('actor_agent_id = @agentId'); params['agentId'] = q.agentId; }
    if (q.since !== undefined) { where.push('ts >= @since'); params['since'] = q.since; }
    if (q.until !== undefined) { where.push('ts <= @until'); params['until'] = q.until; }

    const sql = [
      'SELECT * FROM events',
      where.length ? `WHERE ${where.join(' AND ')}` : '',
      'ORDER BY seq ASC',
      q.limit !== undefined ? 'LIMIT @limit' : '',
      q.offset !== undefined ? 'OFFSET @offset' : '',
    ].filter(Boolean).join(' ');

    if (q.limit !== undefined) params['limit'] = q.limit;
    if (q.offset !== undefined) params['offset'] = q.offset;

    return this.db.prepare(sql).all(params) as IndexedEvent[];
  }

  count(): number {
    return (this.db.prepare('SELECT COUNT(*) AS n FROM events').get() as { n: number }).n;
  }

  countByKind(): Record<string, number> {
    const rows = this.db.prepare('SELECT kind, COUNT(*) AS n FROM events GROUP BY kind').all() as
      { kind: string; n: number }[];
    return Object.fromEntries(rows.map((r) => [r.kind, r.n]));
  }

  close(): void {
    this.db.close();
  }
}

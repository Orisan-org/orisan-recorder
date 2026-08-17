/**
 * Issue #2b — retention that does not destroy the evidence.
 *
 * A log only grows, and issue #2 measured what that costs. But deleting old
 * events is EXACTLY the truncation attack the whole product exists to catch,
 * so "just prune" is not available. The distinction has to be built.
 *
 * THE IDEA: prune events, keep checkpoints and anchors.
 *
 * A checkpoint is a few hundred bytes committing to a Merkle root over its
 * range; the events are the megabytes. Removing the events while keeping the
 * signed, externally timestamped checkpoint leaves behind proof of exactly
 * what used to be there — the root still commits to the pruned content, and it
 * was timestamped before anyone could have chosen what to delete. So a pruned
 * range is not a hole in the evidence. It is a range whose contents are no
 * longer available but whose fingerprint still is.
 *
 * Four rules make it safe, and verify enforces all of them:
 *
 * 1. WHOLE RANGES ONLY. Never part of a checkpoint. Half a range would make
 *    the retained root uncheckable forever — it could never be recomputed and
 *    could never be shown to be wrong.
 * 2. ANCHORED RANGES ONLY. Without an external timestamp there is no proof of
 *    what the range contained before someone decided to delete it, so the
 *    prune would destroy evidence rather than compact it.
 * 3. IT IS RECORDED IN THE LOG. A `prune` event is appended to the chain, and
 *    its args_digest commits to the manifest entry. The event is then covered
 *    by the next checkpoint and anchor like any other, so the prune itself
 *    becomes tamper-evident and timestamped.
 * 4. THE CHAIN STAYS WALKABLE. The manifest records the hash of the last event
 *    removed, so the event after the gap can still be linked to what preceded
 *    it. Without that the chain would break at every prune and be
 *    indistinguishable from tampering — which is the entire point.
 *
 * What this deliberately does NOT claim: pruning is not reversible and a
 * pruned range's content cannot be recovered from the log. It is a decision to
 * keep the proof and drop the detail, taken on purpose and on the record.
 */

import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { canonicalJson, type RecordedEvent } from './schema.js';
import { readCheckpoints, type SignedCheckpoint } from './checkpoint.js';
import { readAnchor } from './tsa.js';
import { EventStore, listSegments, splitLines } from './store.js';

export const PRUNES_FILENAME = 'prunes.jsonl';

/** One pruned checkpoint range. Everything needed to check the gap is here. */
export interface PrunedRange {
  checkpoint_index: number;
  seq_from: number;
  seq_to: number;
  /** Events removed. Must equal the checkpoint's count. */
  count: number;
  /** The anchored root the removed events hashed to. Retained as the proof. */
  merkle_root: string;
  /** Hash of the last event removed, so the chain can be walked across the gap. */
  last_event_hash: string;
  /** prev_hash of the first event removed, so the join is checkable from both ends. */
  first_prev_hash: string;
}

export interface PruneRecord {
  v: 1;
  pruned_at: string;
  reason: string;
  ranges: PrunedRange[];
}

/** What the prune event's args_digest commits to. */
export function pruneDigest(record: PruneRecord): string {
  return createHash('sha256').update(canonicalJson(record), 'utf8').digest('hex');
}

export function readPruneRecords(dir: string): PruneRecord[] {
  const path = join(dir, PRUNES_FILENAME);
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8').split('\n').filter((l) => l.trim())
    .map((l) => JSON.parse(l) as PruneRecord);
}

/** Every pruned range across every record, sorted by seq_from. */
export function prunedRanges(dir: string): PrunedRange[] {
  return readPruneRecords(dir).flatMap((r) => r.ranges).sort((a, b) => a.seq_from - b.seq_from);
}

export interface PruneCandidate {
  checkpoint: SignedCheckpoint;
  eligible: boolean;
  /** Why not, when it is not. */
  blocked?: string;
}

export interface PruneSelection {
  candidates: PruneCandidate[];
  eligible: SignedCheckpoint[];
}

export interface PruneOptions {
  /** Prune ranges whose checkpoint was created strictly before this. */
  before?: Date;
  /** Keep this many of the newest checkpoint ranges, prune the rest. */
  keepLast?: number;
  reason?: string;
  now?: () => Date;
}

/**
 * Decide what may be pruned, and say why for everything that may not.
 *
 * The newest checkpoint is never a candidate: events after it are uncommitted
 * and pruning around them would leave the head unverifiable.
 */
export function selectForPrune(dir: string, opts: PruneOptions): PruneSelection {
  const checkpoints = readCheckpoints(dir);
  const alreadyPruned = new Set(prunedRanges(dir).map((r) => r.checkpoint_index));

  const candidates: PruneCandidate[] = checkpoints.map((cp) => {
    if (alreadyPruned.has(cp.index)) return { checkpoint: cp, eligible: false, blocked: 'already pruned' };
    if (readAnchor(dir, cp.seq_to) === null) {
      // Rule 2. This is the one people will want to override, and it is the
      // one that must not be overridable: an unanchored range has no external
      // proof of its contents, so removing it destroys evidence.
      return { checkpoint: cp, eligible: false, blocked: 'not anchored: no external proof of what it contained' };
    }
    if (cp.index === checkpoints[checkpoints.length - 1]!.index) {
      return { checkpoint: cp, eligible: false, blocked: 'newest checkpoint; events after it are uncommitted' };
    }
    if (opts.before && new Date(cp.created_at) >= opts.before) {
      return { checkpoint: cp, eligible: false, blocked: `created ${cp.created_at}, not before ${opts.before.toISOString()}` };
    }
    return { checkpoint: cp, eligible: true };
  });

  let eligible = candidates.filter((c) => c.eligible).map((c) => c.checkpoint);

  if (opts.keepLast !== undefined) {
    // Counted over ALL checkpoints, not just eligible ones: "keep the last 5"
    // has to mean five ranges of history, whatever their anchor state.
    // `slice(-0)` is `slice(0)`, i.e. the whole array — so --keep-last 0 kept
    // everything instead of nothing. Caught by the test for it.
    const n = Math.max(0, opts.keepLast);
    const keep = new Set((n === 0 ? [] : checkpoints.slice(-n)).map((c) => c.index));
    for (const c of candidates) {
      if (c.eligible && keep.has(c.checkpoint.index)) {
        c.eligible = false;
        c.blocked = `within the newest ${opts.keepLast} checkpoint(s)`;
      }
    }
    eligible = candidates.filter((c) => c.eligible).map((c) => c.checkpoint);
  }

  return { candidates, eligible };
}

export interface PruneResult {
  ranges: PrunedRange[];
  eventsRemoved: number;
  bytesFreed: number;
  record: PruneRecord | null;
  /** The prune event appended to the chain, or null on a dry run. */
  event: RecordedEvent | null;
}

/**
 * Remove the events of every eligible range and record that it happened.
 *
 * Order matters and is the opposite of the intuitive one: the manifest and the
 * chain record are written FIRST, and only then are the events removed. A
 * crash between the two leaves a log that claims a prune which has not
 * happened yet — harmless, the events are simply still there — whereas the
 * other order leaves an unexplained gap, which verify correctly calls
 * tampering.
 */
export function prune(dir: string, opts: PruneOptions & { dryRun?: boolean } = {}): PruneResult {
  const { eligible } = selectForPrune(dir, opts);
  if (eligible.length === 0) {
    return { ranges: [], eventsRemoved: 0, bytesFreed: 0, record: null, event: null };
  }

  // Read the boundary hashes before anything is removed. Without these the
  // chain cannot be walked across the gap afterwards.
  const wanted = new Map<number, SignedCheckpoint>();
  for (const cp of eligible) wanted.set(cp.seq_to, cp);
  const firstPrev = new Map<number, string>();
  const lastHash = new Map<number, string>();
  const present = new Map<number, number>();

  {
    const reader = EventStore.open(dir, { readOnly: true }).store;
    for (const e of reader.read()) {
      for (const cp of eligible) {
        if (e.seq < cp.seq_from || e.seq > cp.seq_to) continue;
        if (e.seq === cp.seq_from) firstPrev.set(cp.seq_to, e.prev_hash);
        lastHash.set(cp.seq_to, e.hash);
        present.set(cp.seq_to, (present.get(cp.seq_to) ?? 0) + 1);
      }
    }
  }

  const ranges: PrunedRange[] = [];
  for (const cp of eligible) {
    const count = present.get(cp.seq_to) ?? 0;
    // Rule 1, checked rather than assumed. If the range is not all there, the
    // log is already wrong and pruning would bury the discrepancy.
    if (count !== cp.count) {
      throw new Error(
        `refusing to prune checkpoint ${cp.index} (${cp.seq_from}..${cp.seq_to}): it commits to ${cp.count} `
        + `events but ${count} are present. Run verify — this log has a problem that pruning would hide.`,
      );
    }
    ranges.push({
      checkpoint_index: cp.index,
      seq_from: cp.seq_from,
      seq_to: cp.seq_to,
      count,
      merkle_root: cp.merkle_root,
      last_event_hash: lastHash.get(cp.seq_to)!,
      first_prev_hash: firstPrev.get(cp.seq_to)!,
    });
  }

  const eventsRemoved = ranges.reduce((n, r) => n + r.count, 0);
  if (opts.dryRun) {
    return { ranges, eventsRemoved, bytesFreed: 0, record: null, event: null };
  }

  const record: PruneRecord = {
    v: 1,
    pruned_at: (opts.now?.() ?? new Date()).toISOString(),
    reason: opts.reason ?? 'retention',
    ranges,
  };

  // 1. the manifest
  appendFileSync(join(dir, PRUNES_FILENAME), `${JSON.stringify(record)}\n`, { mode: 0o644 });

  // 2. the record in the chain, committing to the manifest by digest
  const store = EventStore.open(dir).store;
  let event: RecordedEvent;
  try {
    event = store.append({
      actor: { human: null, agent_id: 'orisan-rec', tool: 'prune' },
      kind: 'prune',
      target: ranges.map((r) => `${r.seq_from}..${r.seq_to}`).join(','),
      args_digest: pruneDigest(record),
      payload_ref: null,
      outcome: 'ok',
      duration_ms: null,
    });
  } finally {
    store.close();
  }

  // 3. and only now, the events
  const bytesFreed = removeEvents(dir, ranges);

  return { ranges, eventsRemoved, bytesFreed, record, event };
}

/** Rewrite the segments, dropping every line inside a pruned range. */
function removeEvents(dir: string, ranges: readonly PrunedRange[]): number {
  const inRange = (seq: number): boolean => ranges.some((r) => seq >= r.seq_from && seq <= r.seq_to);
  let freed = 0;

  for (const name of listSegments(dir)) {
    const path = join(dir, name);
    const before = readFileSync(path);
    const { lines, remainder } = splitLines(before);
    const nonEmpty = lines.filter((l) => l.length > 0);
    const kept = nonEmpty.filter((line) => !inRange((JSON.parse(line) as { seq: number }).seq));
    if (kept.length === nonEmpty.length) continue;

    const body = Buffer.from(kept.map((l) => `${l}\n`).join(''), 'utf8');
    // The remainder is a torn tail the reader would discard anyway; carried
    // through so pruning never repairs something verify should be reporting.
    const after = Buffer.concat([body, remainder]);
    writeFileSync(path, after);
    freed += before.length - after.length;
  }
  return freed;
}

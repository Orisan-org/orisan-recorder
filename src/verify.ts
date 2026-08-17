/**
 * R1.4 — the verify command.
 *
 * Four checks, in order, per spec:
 *   1. Walk the chain from genesis. Any break: FAIL naming the exact seq.
 *   2. Check every checkpoint signature against the public key.
 *   3. Check every .tsr with openssl against the TSA cert.
 *   4. Detect the recompute attack: chain internally consistent, but the
 *      latest anchored checkpoint's merkle_root does not match the events
 *      actually present. FAIL naming the checkpoint.
 *
 * Exit codes: 0 clean, 1 tampered, 2 cannot-verify.
 *
 * The third code is the one that matters most and the one competitors get
 * wrong. "I could not check" is not "it is fine". A missing anchor, a missing
 * public key, an openssl that will not run — each yields 2, never 0. The only
 * route to 0 is that every check actually ran and every check passed.
 *
 * Step 3 shells out. We never verify our own time proof: openssl and the TSA's
 * CA decide, and the exact command is printed so a reviewer can re-run it by
 * hand and trust none of this code.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { isAbsolute, join, resolve, sep } from 'node:path';

import {
  PUBLIC_KEY_FILENAME,
  SIGNING_KEY_FILENAME,
  anchorDigest,
  readCheckpoints,
  verifyCheckpointChain,
  verifyCheckpointSignature,
  type SignedCheckpoint,
} from './checkpoint.js';
import { merkleRoot } from './merkle.js';
import { EventStore } from './store.js';
import { anchorPaths, readAnchor, readAttestedTime } from './tsa.js';
import { highestWitnessedIndex, readWitness, verifyAgainstWitness } from './witness.js';
import { ChainWalker, computeEventHash, type ChainBreak, type RecordedEvent } from './schema.js';
import { MerkleAccumulator } from './merkle.js';
import { PRUNES_FILENAME, pruneDigest, readPruneRecords, type PrunedRange } from './prune.js';

/**
 * At most this many chain breaks are reported individually.
 *
 * A thoroughly mangled log can break at every event, and one finding each
 * would put the whole log back in memory through the side door — the exact
 * thing issue #2 is about. The count is still reported in full; it is the
 * per-event detail that stops.
 */
export const MAX_REPORTED_CHAIN_BREAKS = 50;

/** What one streaming pass over the events yields, per checkpoint range. */
interface RangeSummary {
  /** Events actually present inside the range. */
  present: number;
  /** RFC 6962 root over those events, recomputed from content. */
  root: string;
  /** Newest event timestamp inside the range, for the anchor freshness check. */
  newestTs: Date | null;
}

interface EventScan {
  total: number;
  headSeq: number;
  chainBreaks: ChainBreak[];
  chainBreakTotal: number;
  /** Keyed by checkpoint seq_to. */
  ranges: Map<number, RangeSummary>;
  /** Events with seq strictly greater than the highest anchored seq_to. */
  pastLastAnchor: number;
  /** Prune boundaries the chain walk could not join up. */
  pruneJoinFailures: string[];
}

/**
 * Walk the log once, computing everything the checks need.
 *
 * Verify used to call `store.readAll()` and hold the log in memory: 691 MB of
 * peak RSS at 300k events, growing linearly, so a long-running install
 * eventually reached the size where its own verifier would not run. Nothing
 * here needs random access — the chain walk is sequential, and each
 * checkpoint's Merkle root only needs the events in its own range, in order.
 *
 * Only ONE Merkle accumulator is live at a time. Checkpoint ranges are sorted
 * and disjoint, so a range is finalised to a 64-character root the moment the
 * events pass its seq_to, and the accumulator is dropped. Combined with
 * MerkleAccumulator's O(log n) stack, memory does not grow with the log.
 */
function scanEvents(
  store: EventStore,
  checkpoints: readonly SignedCheckpoint[],
  lastAnchoredSeq: number,
  pruned: readonly PrunedRange[] = [],
): EventScan {
  // A recorded prune is a legitimate discontinuity, so the walker is restarted
  // on the far side of each one using the hash the manifest recorded. An
  // UNRECORDED gap gets no such treatment and still breaks the chain, which is
  // the whole distinction (issue #2b).
  const gaps = [...pruned].sort((a, b) => a.seq_from - b.seq_from);
  const pruneJoinFailures: string[] = [];
  let walker = new ChainWalker();
  let nextGap = 0;
  const chainBreaks: ChainBreak[] = [];
  const ranges = new Map<number, RangeSummary>();

  // Sorted by seq_from so a single pointer keeps pace with the events. The
  // checkpoint chain check reports discontinuity separately; this only needs
  // them in order to know which range an event belongs to.
  const ordered = [...checkpoints].sort((a, b) => a.seq_from - b.seq_from);
  let cpIdx = 0;
  let open: { cp: SignedCheckpoint; merkle: MerkleAccumulator; newest: number | null } | null = null;

  const closeOpen = (): void => {
    if (!open) return;
    ranges.set(open.cp.seq_to, {
      present: open.merkle.count,
      root: open.merkle.root(),
      newestTs: open.newest === null ? null : new Date(open.newest),
    });
    open = null;
  };

  let total = 0;
  let headSeq = -1;
  let chainBreakTotal = 0;
  let pastLastAnchor = 0;

  for (const e of store.read()) {
    total++;
    headSeq = e.seq;
    if (e.seq > lastAnchoredSeq) pastLastAnchor++;

    // Crossed a pruned range: resume from the recorded boundary hash instead
    // of reporting the gap the removal necessarily left.
    while (nextGap < gaps.length && e.seq > gaps[nextGap]!.seq_to) {
      const g = gaps[nextGap]!;
      walker = new ChainWalker(g.last_event_hash, g.seq_to + 1);
      nextGap++;
    }

    for (const b of walker.push(e)) {
      chainBreakTotal++;
      if (chainBreaks.length < MAX_REPORTED_CHAIN_BREAKS) chainBreaks.push(b);
    }

    // Finish any range this event has moved past, then open the one it is in.
    while (open && e.seq > open.cp.seq_to) closeOpen();
    while (!open && cpIdx < ordered.length && ordered[cpIdx]!.seq_to < e.seq) {
      // A range with no events left in it at all: record it as empty so the
      // count check still fires rather than the range silently vanishing.
      const skipped = ordered[cpIdx]!;
      if (!ranges.has(skipped.seq_to)) {
        ranges.set(skipped.seq_to, { present: 0, root: new MerkleAccumulator().root(), newestTs: null });
      }
      cpIdx++;
    }
    if (!open && cpIdx < ordered.length && e.seq >= ordered[cpIdx]!.seq_from && e.seq <= ordered[cpIdx]!.seq_to) {
      open = { cp: ordered[cpIdx]!, merkle: new MerkleAccumulator(), newest: null };
      cpIdx++;
    }

    if (open && e.seq >= open.cp.seq_from && e.seq <= open.cp.seq_to) {
      open.merkle.push(computeEventHash(stripHash(e)));
      const t = Date.parse(e.ts);
      if (!Number.isNaN(t) && (open.newest === null || t > open.newest)) open.newest = t;
    }
  }
  closeOpen();

  // The manifest's boundary hashes are only worth something if they line up
  // with what is still there. A prune whose first_prev_hash does not match the
  // event before the gap is a prune record written to excuse a different
  // deletion.
  if (gaps.length > 0) {
    const boundaries = new Map<number, RecordedEvent>();
    const wanted = new Set<number>();
    for (const g of gaps) { wanted.add(g.seq_from - 1); wanted.add(g.seq_to + 1); }
    for (const e of store.read()) if (wanted.has(e.seq)) boundaries.set(e.seq, e);
    for (const g of gaps) {
      const before = boundaries.get(g.seq_from - 1);
      if (before && before.hash !== g.first_prev_hash) {
        pruneJoinFailures.push(
          `prune of ${g.seq_from}..${g.seq_to} records first_prev_hash ${g.first_prev_hash.slice(0, 12)}… `
          + `but seq ${g.seq_from - 1} hashes to ${before.hash.slice(0, 12)}…`,
        );
      }
      const after = boundaries.get(g.seq_to + 1);
      if (after && after.prev_hash !== g.last_event_hash) {
        pruneJoinFailures.push(
          `prune of ${g.seq_from}..${g.seq_to} records last_event_hash ${g.last_event_hash.slice(0, 12)}… `
          + `but seq ${g.seq_to + 1} follows ${after.prev_hash.slice(0, 12)}…`,
        );
      }
    }
  }

  // Checkpoints entirely beyond the end of the log still need a summary, or
  // the count check would have nothing to compare against and truncation
  // below an anchor would lose one of its two signals.
  for (const cp of ordered) {
    if (!ranges.has(cp.seq_to)) {
      ranges.set(cp.seq_to, { present: 0, root: new MerkleAccumulator().root(), newestTs: null });
    }
  }

  return { total, headSeq, chainBreaks, chainBreakTotal, ranges, pastLastAnchor, pruneJoinFailures };
}

/** An event minus its stored hash, ready for recomputation. */
function stripHash(e: RecordedEvent): Omit<RecordedEvent, 'hash'> {
  const { hash: _drop, ...rest } = e;
  return rest;
}

/**
 * How long after the newest event it covers an anchor may be attested.
 *
 * An anchor is meant to say "this happened before T". If the operator can
 * delete history and re-anchor it today, the timestamp attests only to the
 * rewrite. A window is needed because anchoring is not instantaneous and may
 * be drained from an offline queue, but it must be short enough that
 * back-dating a session is not free.
 */
export const ANCHOR_FRESHNESS_MS = 60 * 60 * 1000;

export const EXIT_CLEAN = 0;
export const EXIT_TAMPERED = 1;
export const EXIT_CANNOT_VERIFY = 2;

export type Verdict = 'clean' | 'tampered' | 'cannot_verify';

export interface Finding {
  severity: 'tampered' | 'cannot_verify';
  code: string;
  message: string;
  /** Where the problem is, when it can be named precisely. */
  seq?: number;
  checkpoint_seq_to?: number;
}

export interface VerifyReport {
  verdict: Verdict;
  exitCode: number;
  events: number;
  /** Events removed by a recorded, chain-vouched retention prune (issue #2b). */
  prunedEvents: number;
  checkpoints: number;
  anchored: number;
  findings: Finding[];
  /** openssl invocations run, verbatim, so a reviewer can repeat them. */
  opensslCommands: string[];
  /** Attested time per checkpoint seq_to, as read from the token. */
  attestedTimes: { checkpoint_seq_to: number; attested_at: string }[];
}

/**
 * W1.5 — what the witness service told us, already fetched.
 *
 * verify() stays synchronous and pure: the caller does the network I/O and
 * hands the result in. That keeps every decision below testable without a
 * socket, which matters more here than anywhere else in the codebase.
 */
export interface WitnessServiceInput {
  /** From witness.json in the log directory. */
  logId: string;
  url: string;
  /** Whether the head could be fetched at all. */
  reachable: boolean;
  error?: string;
  /** Whether the head's signature verified against the PINNED key. */
  signatureValid?: boolean;
  head?: {
    log_id: string;
    latest_index: number;
    latest_seq_to: number;
    merkle_root: string;
    witnessed_at: string;
    conflict: boolean;
    conflict_count: number;
  };
}

export interface VerifyOptions {
  /** CA bundle for the TSA. Without it the anchor check cannot run → exit 2. */
  tsaCaFile?: string;
  /**
   * External witness LOG FILE — the weaker, self-hosted form. Without either
   * this or a witness service, completeness cannot be established and a clean
   * verdict is unreachable: tail truncation leaves a valid prefix.
   */
  witnessFile?: string;
  /** External witness SERVICE head, already fetched by the caller. */
  witnessService?: WitnessServiceInput;
  /** Override the openssl binary. Must be an absolute path. */
  opensslPath?: string;
  /** Expected TSA URL. An anchor recorded against any other authority is a finding. */
  expectedTsaUrl?: string;
  /** Skip shelling out (used by tests that assert the cannot-verify path). */
  skipOpenssl?: boolean;
}

function worst(findings: readonly Finding[]): Verdict {
  if (findings.some((f) => f.severity === 'tampered')) return 'tampered';
  if (findings.some((f) => f.severity === 'cannot_verify')) return 'cannot_verify';
  return 'clean';
}

export function exitCodeFor(verdict: Verdict): number {
  return verdict === 'clean' ? EXIT_CLEAN : verdict === 'tampered' ? EXIT_TAMPERED : EXIT_CANNOT_VERIFY;
}

/**
 * Step 4, the important one.
 *
 * A rewritten-and-re-sealed chain passes step 1 by construction. What it
 * cannot do is match a Merkle root that was signed and anchored before the
 * rewrite. So: for each anchored checkpoint, recompute the root over the
 * events that are actually present in its seq range and compare.
 */
function checkCheckpointAgainstEvents(
  cp: SignedCheckpoint,
  summary: RangeSummary | undefined,
): Finding | null {
  const inRange = { length: summary?.present ?? 0 };

  if (inRange.length !== cp.count) {
    return {
      severity: 'tampered',
      code: 'checkpoint_count_mismatch',
      checkpoint_seq_to: cp.seq_to,
      message:
        `checkpoint ${cp.seq_from}..${cp.seq_to} commits to ${cp.count} events but ` +
        `${inRange.length} are present — records were added or removed after it was anchored`,
    };
  }

  // Leaves are RECOMPUTED from event content, never taken from the stored
  // e.hash. Trusting the stored field meant the anchored root committed to
  // *claimed* digests: edit an event's outcome, leave its hash alone, and the
  // Merkle check passed unchanged — only the step-1 chain walk objected. The
  // externally anchored layer must confirm content independently or it adds
  // nothing the chain did not already provide.
  const actual = summary?.root ?? '';
  if (actual !== cp.merkle_root) {
    return {
      severity: 'tampered',
      code: 'checkpoint_root_mismatch',
      checkpoint_seq_to: cp.seq_to,
      message:
        `checkpoint ${cp.seq_from}..${cp.seq_to} was anchored to merkle_root ${cp.merkle_root} ` +
        `but the events now present hash to ${actual} — the log was rewritten after anchoring`,
    };
  }
  return null;
}

/**
 * Absolute path to openssl, or null if it cannot be found in a trusted location.
 * An explicit opensslPath is honoured as given (tests rely on that) but must
 * itself be absolute.
 */
/**
 * Is this witness running on the same machine as the recorder?
 *
 * A witness exists to remember what the operator can delete. One on loopback
 * is a file the operator can `rm`, so it provides no external memory at all —
 * and green on that basis would be precisely the false reassurance this
 * project was built to avoid. Narrow on purpose: only loopback is refused. A
 * witness on another host, even one the same company runs, is a deployment
 * question this code cannot answer from a URL.
 */
export function witnessIsLoopback(url: string): boolean {
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase().replace(/^\[|\]$/g, '');
  } catch {
    return false;
  }
  return host === 'localhost' || host === '::1' || host === '0.0.0.0'
    || /^127\./.test(host) || host.endsWith('.localhost');
}

export function resolveOpenssl(explicit?: string): string | null {
  if (explicit !== undefined) return isAbsolute(explicit) ? explicit : null;
  for (const candidate of [
    '/opt/homebrew/bin/openssl',
    '/usr/bin/openssl',
    '/usr/local/bin/openssl',
    '/bin/openssl',
  ]) {
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

/**
 * Public entry point. Any unexpected throw — a corrupt JSONL line, an
 * unreadable anchor, a missing directory — becomes cannot_verify (exit 2).
 *
 * Previously these escaped as an uncaught rejection and the process exited 1,
 * which any calling script reads as TAMPERED. An unreadable file is a gap in
 * the evidence, not proof of wrongdoing, and mislabelling it both cries wolf
 * and destroys the distinction the exit codes exist to make.
 */
export function verify(dir: string, opts: VerifyOptions = {}): VerifyReport {
  try {
    return verifyInner(dir, opts);
  } catch (e) {
    return {
      verdict: 'cannot_verify',
      exitCode: EXIT_CANNOT_VERIFY,
      events: 0,
      prunedEvents: 0,
      checkpoints: 0,
      anchored: 0,
      findings: [{
        severity: 'cannot_verify',
        code: 'unreadable',
        message: `verification could not be completed: ${(e as Error).message}`,
      }],
      opensslCommands: [],
      attestedTimes: [],
    };
  }
}

function verifyInner(dir: string, opts: VerifyOptions = {}): VerifyReport {
  const findings: Finding[] = [];
  const opensslCommands: string[] = [];
  // Resolve to an absolute path. Dispatching by name lets anyone who can set
  // PATH drop in a shim that exits 0, which turns every corrupted token into a
  // verified anchor — and step 3 is the only thing standing between a forged
  // token and a clean verdict.
  const openssl = resolveOpenssl(opts.opensslPath);

  // ---- 1. the chain -------------------------------------------------------
  const { store, recovery } = EventStore.open(dir, { readOnly: true });
  if (recovery.truncatedPartialTail) {
    findings.push({
      severity: 'cannot_verify',
      code: 'partial_tail_discarded',
      message:
        `a ${recovery.bytesDiscarded}-byte partial line was discarded from ${recovery.segment}; ` +
        'the final event may be missing',
    });
  }
  // ---- 2. checkpoint signatures ------------------------------------------
  const checkpoints = readCheckpoints(dir);
  const pubPath = join(dir, PUBLIC_KEY_FILENAME);
  const pubPem = existsSync(pubPath) ? readFileSync(pubPath, 'utf8') : null;

  // Which checkpoints are anchored depends only on the anchor files, so it is
  // known before a single event is read — which is what lets the whole log be
  // walked exactly once, below.
  const anchoredCheckpoints = checkpoints.filter((cp) => readAnchor(dir, cp.seq_to) !== null);
  const lastAnchoredSeq = anchoredCheckpoints.length
    ? Math.max(...anchoredCheckpoints.map((c) => c.seq_to))
    : -1;

  // ---- 1b. recorded prunes ------------------------------------------------
  // A prune record only counts if the chain itself vouches for it: the log
  // must contain a `prune` event whose args_digest is the digest of that
  // manifest entry. A manifest anyone can drop into the directory would be a
  // universal excuse for a deletion, which is exactly what must not exist.
  const pruneRecords = readPruneRecords(dir);
  const claimedDigests = new Map(pruneRecords.map((r) => [pruneDigest(r), r]));
  const vouched = new Set<string>();
  if (pruneRecords.length > 0) {
    for (const e of store.read()) {
      if (e.kind === 'prune' && e.args_digest && claimedDigests.has(e.args_digest)) vouched.add(e.args_digest);
    }
  }
  const acceptedPrunes = pruneRecords.filter((r) => vouched.has(pruneDigest(r)));
  const prunedRanges = acceptedPrunes.flatMap((r) => r.ranges);
  const prunedByCheckpoint = new Map(prunedRanges.map((r) => [r.checkpoint_index, r]));

  for (const r of pruneRecords) {
    if (vouched.has(pruneDigest(r))) continue;
    findings.push({
      severity: 'tampered',
      code: 'prune_not_in_chain',
      message:
        `${PRUNES_FILENAME} claims a prune of ${r.ranges.map((x) => `${x.seq_from}..${x.seq_to}`).join(', ')} `
        + 'but no prune event in the log commits to it. An unvouched manifest is an excuse, not a record',
    });
  }

  // ---- 1c. one pass over the events --------------------------------------
  const scan = scanEvents(store, checkpoints, lastAnchoredSeq, prunedRanges);
  for (const detail of scan.pruneJoinFailures) {
    findings.push({ severity: 'tampered', code: 'prune_boundary_mismatch', message: detail });
  }
  for (const b of scan.chainBreaks) {
    findings.push({
      severity: 'tampered',
      code: `chain_${b.reason}`,
      seq: b.seq,
      message: `chain break at seq ${b.seq}: ${b.reason} (expected ${b.expected}, got ${b.actual})`,
    });
  }
  if (scan.chainBreakTotal > scan.chainBreaks.length) {
    findings.push({
      severity: 'tampered',
      code: 'chain_breaks_truncated',
      message:
        `${scan.chainBreakTotal} chain breaks in total; only the first ${scan.chainBreaks.length} are ` +
        'listed above. A log this damaged should be treated as lost, not repaired',
    });
  }

  // 2a. The checkpoint log must itself be an unbroken chain covering the events
  //     from seq 0. Validating only what is present was the single root cause
  //     of four of the five confirmed exit-0 exploits.
  for (const b of verifyCheckpointChain(checkpoints)) {
    findings.push({
      severity: 'tampered',
      code: `checkpoint_chain_${b.reason}`,
      checkpoint_seq_to: b.seq_to,
      message: b.message,
    });
  }

  if (checkpoints.length === 0) {
    findings.push({
      severity: 'cannot_verify',
      code: 'no_checkpoints',
      message: 'no checkpoints found; the chain alone cannot detect a rewrite',
    });
  } else if (!pubPem) {
    findings.push({
      severity: 'cannot_verify',
      code: 'no_public_key',
      message: `${PUBLIC_KEY_FILENAME} is missing; checkpoint signatures cannot be checked`,
    });
  } else {
    for (const cp of checkpoints) {
      if (!verifyCheckpointSignature(cp, pubPem)) {
        findings.push({
          severity: 'tampered',
          code: 'checkpoint_bad_signature',
          checkpoint_seq_to: cp.seq_to,
          message: `checkpoint ${cp.seq_from}..${cp.seq_to} has an invalid signature`,
        });
      }
    }
  }

  // ---- 3. external anchors ------------------------------------------------
  let anchored = 0;
  const attestedTimes = new Map<number, Date>();
  for (const cp of checkpoints) {
    const rec = readAnchor(dir, cp.seq_to);
    const paths = anchorPaths(dir, cp.seq_to);

    if (!rec || !existsSync(paths.tsr)) {
      findings.push({
        severity: 'cannot_verify',
        code: 'checkpoint_unanchored',
        checkpoint_seq_to: cp.seq_to,
        message:
          `checkpoint ${cp.seq_from}..${cp.seq_to} has no RFC 3161 anchor; ` +
          'its history is not externally committed',
      });
      continue;
    }

    // The anchor must be over THIS checkpoint, not some other one.
    const expected = anchorDigest(cp).toString('hex');
    if (rec.digest !== expected) {
      findings.push({
        severity: 'tampered',
        code: 'anchor_digest_mismatch',
        checkpoint_seq_to: cp.seq_to,
        message:
          `anchor for checkpoint ${cp.seq_to} timestamps digest ${rec.digest} but this ` +
          `checkpoint hashes to ${expected} — the anchor belongs to a different checkpoint`,
      });
      continue;
    }

    if (opts.expectedTsaUrl !== undefined && rec.tsa_url !== opts.expectedTsaUrl) {
      findings.push({
        severity: 'tampered',
        code: 'tsa_url_mismatch',
        checkpoint_seq_to: cp.seq_to,
        message:
          `checkpoint ${cp.seq_to} was anchored to ${rec.tsa_url}, not the expected ` +
          `${opts.expectedTsaUrl}; an operator-chosen authority proves nothing`,
      });
      continue;
    }
    if (opts.skipOpenssl) {
      findings.push({
        severity: 'cannot_verify',
        code: 'tsa_check_skipped',
        checkpoint_seq_to: cp.seq_to,
        message: 'TSA signature check was skipped',
      });
      continue;
    }
    if (openssl === null) {
      findings.push({
        severity: 'cannot_verify',
        code: 'openssl_not_found',
        checkpoint_seq_to: cp.seq_to,
        message:
          'openssl could not be resolved to an absolute path in a trusted location; ' +
          'refusing to dispatch it by name',
      });
      continue;
    }
    if (!opts.tsaCaFile) {
      findings.push({
        severity: 'cannot_verify',
        code: 'no_tsa_ca',
        checkpoint_seq_to: cp.seq_to,
        message:
          'no TSA CA file supplied (--tsa-ca), so the timestamp signature cannot be checked; ' +
          'the anchor is present but unproven',
      });
      continue;
    }
    if (!existsSync(opts.tsaCaFile)) {
      findings.push({
        severity: 'cannot_verify',
        code: 'tsa_ca_missing',
        checkpoint_seq_to: cp.seq_to,
        message: `TSA CA file not found: ${opts.tsaCaFile}`,
      });
      continue;
    }

    const args = ['ts', '-verify', '-digest', rec.digest, '-in', paths.tsr, '-CAfile', opts.tsaCaFile];
    opensslCommands.push([openssl, ...args].join(' '));
    try {
      // We do not parse this output for a verdict beyond exit status: openssl
      // succeeding IS the verdict. Nothing here re-implements the check.
      execFileSync(openssl, args, { stdio: ['ignore', 'pipe', 'pipe'] });

      // The signature is good; now ask what time it claims. Only meaningful
      // after the signature check, which is why it lives here and not earlier.
      const attested = readAttestedTime(openssl, paths.tsr);
      if (attested === null) {
        findings.push({
          severity: 'cannot_verify',
          code: 'anchor_time_unreadable',
          checkpoint_seq_to: cp.seq_to,
          message: `could not read the attested time from the token for checkpoint ${cp.seq_to}`,
        });
        continue;
      }
      attestedTimes.set(cp.seq_to, attested);

      const newestEventTs = scan.ranges.get(cp.seq_to)?.newestTs ?? null;
      if (newestEventTs !== null) {
        const skewMs = attested.getTime() - newestEventTs.getTime();
        if (skewMs > ANCHOR_FRESHNESS_MS) {
          findings.push({
            severity: 'tampered',
            code: 'anchor_too_late',
            checkpoint_seq_to: cp.seq_to,
            message:
              `checkpoint ${cp.seq_from}..${cp.seq_to} covers events up to ` +
              `${newestEventTs.toISOString()} but was timestamped ${attested.toISOString()}, ` +
              `${Math.round(skewMs / 60000)} minutes later (limit ` +
              `${Math.round(ANCHOR_FRESHNESS_MS / 60000)}); the anchor attests to a re-anchoring, ` +
              'not to when the events happened',
          });
          continue;
        }
      }
      anchored++;
    } catch (e) {
      const err = e as { status?: number | null; code?: string; stderr?: Buffer };
      const detail = (err.stderr?.toString() ?? '').trim().split('\n').slice(-1)[0] ?? '';
      // Distinguish "openssl ran and said no" from "openssl never ran".
      // A spawn failure sets status to NULL (not undefined) and code to e.g.
      // ENOENT; only a real invocation yields a numeric exit status. Getting
      // this wrong reports a missing openssl as TAMPERED, which is both a
      // false accusation and a way to lose the cannot-verify signal entirely.
      const opensslActuallyRan = typeof err.status === 'number';
      if (!opensslActuallyRan) {
        findings.push({
          severity: 'cannot_verify',
          code: 'openssl_unavailable',
          checkpoint_seq_to: cp.seq_to,
          message: `could not run ${openssl} (${err.code ?? 'spawn failed'}): ${detail || (e as Error).message}`,
        });
      } else {
        findings.push({
          severity: 'tampered',
          code: 'tsa_verification_failed',
          checkpoint_seq_to: cp.seq_to,
          message: `openssl rejected the timestamp for checkpoint ${cp.seq_to}: ${detail}`,
        });
      }
    }
  }

  // ---- 4. the recompute attack -------------------------------------------
  // Only meaningful against checkpoints that are actually anchored: an
  // unanchored checkpoint can simply be re-signed alongside the rewrite.
  for (const cp of anchoredCheckpoints) {
    const pruneOfThis = prunedByCheckpoint.get(cp.index);
    if (pruneOfThis) {
      // The events are gone on purpose. What is checked instead is that the
      // manifest describes THIS checkpoint: same range, same count, same root.
      // The anchored root is retained precisely so the removal cannot be used
      // to swap a range for a different one.
      const consistent =
        pruneOfThis.seq_from === cp.seq_from &&
        pruneOfThis.seq_to === cp.seq_to &&
        pruneOfThis.count === cp.count &&
        pruneOfThis.merkle_root === cp.merkle_root;
      if (!consistent) {
        findings.push({
          severity: 'tampered',
          code: 'prune_describes_a_different_range',
          checkpoint_seq_to: cp.seq_to,
          message:
            `the prune record for checkpoint ${cp.index} says ${pruneOfThis.seq_from}..${pruneOfThis.seq_to} `
            + `(${pruneOfThis.count} events, root ${pruneOfThis.merkle_root.slice(0, 12)}…) but the anchored `
            + `checkpoint says ${cp.seq_from}..${cp.seq_to} (${cp.count} events, root ${cp.merkle_root.slice(0, 12)}…)`,
        });
        continue;
      }
      const stillPresent = scan.ranges.get(cp.seq_to)?.present ?? 0;
      if (stillPresent !== 0) {
        findings.push({
          severity: 'cannot_verify',
          code: 'prune_incomplete',
          checkpoint_seq_to: cp.seq_to,
          message:
            `checkpoint ${cp.index} is recorded as pruned but ${stillPresent} of its events are still present; `
            + 'the prune did not finish. Re-run `orisan-rec prune`',
        });
      }
      continue;
    }
    const f = checkCheckpointAgainstEvents(cp, scan.ranges.get(cp.seq_to));
    if (f) findings.push(f);
  }

  // ---- 5. head coverage ---------------------------------------------------
  // The highest anchored seq_to is compared against the ACTUAL head of the
  // event log. Previously this only produced a warning, and the "last anchored
  // seq" was derived from whatever checkpoints survived — so deleting the
  // newest checkpoint together with the events it covered moved the goalposts
  // and the truncation became invisible. Both halves are now failures.
  const headSeq = scan.headSeq;

  if (headSeq > lastAnchoredSeq) {
    const uncommitted = scan.pastLastAnchor;
    // cannot_verify, not tampered: events accumulate past the last checkpoint
    // during normal recording, before the cadence fires. Calling that
    // tampering would flag every live log and every `demo` run. It is still
    // never clean — those events are committed to by nothing.
    findings.push({
      severity: 'cannot_verify',
      code: 'events_past_last_anchor',
      message:
        `${uncommitted} event(s) after seq ${lastAnchoredSeq} are covered by no anchored ` +
        `checkpoint (log head is seq ${headSeq}); they are uncommitted`,
    });
  } else if (lastAnchoredSeq > headSeq) {
    // A checkpoint commits to events that are no longer there at all.
    const culprit = anchoredCheckpoints.find((c) => c.seq_to === lastAnchoredSeq);
    findings.push({
      severity: 'tampered',
      code: 'log_truncated_below_anchor',
      ...(culprit ? { checkpoint_seq_to: culprit.seq_to } : {}),
      message:
        `an anchored checkpoint commits up to seq ${lastAnchoredSeq} but the log head is ` +
        `seq ${headSeq}; ${lastAnchoredSeq - headSeq} event(s) were removed from the tail`,
    });
  }

  // ---- 5b. key custody ----------------------------------------------------
  // A signing key inside the log directory means whoever can rewrite the events
  // can re-sign the checkpoints over them, so the signature attests to nothing
  // an attacker could not reproduce.
  if (existsSync(join(dir, SIGNING_KEY_FILENAME))) {
    findings.push({
      severity: 'cannot_verify',
      code: 'signing_key_beside_data',
      message:
        `the signing key is stored in ${dir}, beside the data it authenticates; anyone who ` +
        'can rewrite the log can re-sign it. Move it outside and re-anchor.',
    });
  }

  // ---- 6. the external witness -------------------------------------------
  // Nothing above can detect suffix deletion: truncating events together with
  // the checkpoints covering them leaves a valid prefix. Only a record held
  // outside the operator's control knows a later checkpoint ever existed.
  //
  // W1.5: the service is the strong form. Its head is signed by a key pinned at
  // registration, so a substituted witness cannot answer for it.
  let serviceSatisfiesCompleteness = false;
  if (opts.witnessService !== undefined) {
    const ws = opts.witnessService;

    if (!ws.reachable || !ws.head) {
      // Unreachable is a gap, never a pass, and never an accusation: the
      // network being down is not evidence of wrongdoing.
      findings.push({
        severity: 'cannot_verify',
        code: 'witness_unreachable',
        message:
          `could not reach the witness at ${ws.url}: ${ws.error ?? 'unknown error'}. ` +
          'Completeness cannot be established while the witness is unavailable.',
      });
    } else if (ws.signatureValid !== true) {
      // A head that does not verify against the PINNED key is an attack, not a
      // gap. Someone is answering for the witness who is not the witness.
      findings.push({
        severity: 'tampered',
        code: 'witness_signature_invalid',
        message:
          `the head returned by ${ws.url} is not signed by the pinned witness key. ` +
          'Either the witness was substituted or the response was forged; do not re-pin.',
      });
    } else if (ws.head.log_id !== ws.logId) {
      findings.push({
        severity: 'tampered',
        code: 'witness_wrong_log',
        message: `the witness answered for log ${ws.head.log_id}, not ${ws.logId}`,
      });
    } else if (ws.head.conflict) {
      // The witness saw two different contents for one index: someone re-sealed
      // the log and tried to have the new version witnessed.
      findings.push({
        severity: 'tampered',
        code: 'fork_detected',
        message:
          `the witness has recorded ${ws.head.conflict_count} conflicting submission(s) for this log: ` +
          'a checkpoint index was submitted twice with different content, which means the log was re-sealed',
      });
    } else {
      const localMax = checkpoints.length ? Math.max(...checkpoints.map((c) => c.index)) : -1;
      const localHeadSeq = scan.headSeq;

      if (ws.head.latest_index > localMax) {
        // THE A1 KILL. The witness remembers checkpoints this log no longer has.
        const missing: number[] = [];
        for (let i = localMax + 1; i <= ws.head.latest_index; i++) missing.push(i);
        findings.push({
          severity: 'tampered',
          code: 'truncation_detected',
          message:
            `the witness holds checkpoint(s) ${missing.join(', ')} (up to seq ${ws.head.latest_seq_to}) ` +
            `that are absent from this log, whose last checkpoint is index ${localMax} ` +
            `and whose last event is seq ${localHeadSeq}; the tail was removed`,
        });
      } else {
        const atIndex = checkpoints.find((c) => c.index === ws.head!.latest_index);
        if (atIndex && atIndex.merkle_root !== ws.head.merkle_root) {
          findings.push({
            severity: 'tampered',
            code: 'witness_mismatch',
            message:
              `checkpoint ${ws.head.latest_index} has merkle_root ${atIndex.merkle_root} locally but the ` +
              `witness recorded ${ws.head.merkle_root}; the log was rewritten after being witnessed`,
          });
        } else if (atIndex && atIndex.seq_to !== ws.head.latest_seq_to) {
          findings.push({
            severity: 'tampered',
            code: 'witness_mismatch',
            message:
              `checkpoint ${ws.head.latest_index} ends at seq ${atIndex.seq_to} locally but the witness ` +
              `recorded ${ws.head.latest_seq_to}`,
          });
        } else if (ws.head.latest_index < localMax) {
          // Local is ahead: checkpoints exist that were never witnessed. Not
          // tampering — the queue may simply not have drained — but the log is
          // not fully committed, so it cannot be clean.
          findings.push({
            severity: 'cannot_verify',
            code: 'checkpoints_not_witnessed',
            message:
              `checkpoint(s) after index ${ws.head.latest_index} have not been submitted to the witness; ` +
              'they are not externally committed yet',
          });
        } else if (witnessIsLoopback(ws.url)) {
          // Everything agreed — but with a witness on this machine, agreement
          // proves only that the log agrees with itself.
          findings.push({
            severity: 'cannot_verify',
            code: 'witness_on_localhost',
            message:
              `the witness at ${ws.url} runs on this machine, so it is under the same control as the log ` +
              'it is meant to vouch for; completeness cannot be established against it',
          });
        } else {
          serviceSatisfiesCompleteness = true;
        }
      }
    }
  }

  if (opts.witnessFile === undefined && !serviceSatisfiesCompleteness && opts.witnessService === undefined) {
    findings.push({
      severity: 'cannot_verify',
      code: 'no_witness',
      message:
        'no witness log supplied (--witness), so completeness cannot be established: ' +
        'deleting trailing events together with the checkpoints covering them leaves a ' +
        'valid prefix that is indistinguishable from a log that ended earlier',
    });
  } else if (opts.witnessFile !== undefined && !existsSync(opts.witnessFile)) {
    findings.push({
      severity: 'cannot_verify',
      code: 'witness_missing',
      message: `witness log not found: ${opts.witnessFile}`,
    });
  } else if (opts.witnessFile !== undefined) {
    const witness = readWitness(opts.witnessFile);
    if (witness.length === 0) {
      findings.push({
        severity: 'cannot_verify',
        code: 'witness_empty',
        message: `witness log ${opts.witnessFile} is empty; it attests to nothing`,
      });
    }
    for (const b of verifyAgainstWitness(checkpoints, witness)) {
      findings.push({
        severity: 'tampered',
        code: `witness_${b.reason}`,
        checkpoint_seq_to: checkpoints.find((c) => c.index === b.index)?.seq_to ?? -1,
        message: b.message,
      });
    }
    // A witness kept inside the log directory is under the same hand that
    // writes the log, so it proves nothing. Say so rather than counting it.
    if (resolve(opts.witnessFile).startsWith(resolve(dir) + sep)) {
      findings.push({
        severity: 'cannot_verify',
        code: 'witness_inside_log_dir',
        message:
          `the witness log lives inside ${dir}, under the same control as the data it ` +
          'attests to; move it somewhere the recorder operator cannot rewrite',
      });
    }
    void highestWitnessedIndex;
  }

  const verdict = worst(findings);
  return {
    verdict,
    exitCode: exitCodeFor(verdict),
    events: scan.total,
    prunedEvents: prunedRanges.reduce((n, r) => n + r.count, 0),
    checkpoints: checkpoints.length,
    anchored,
    findings,
    opensslCommands,
    attestedTimes: [...attestedTimes.entries()]
      .sort((a, b) => a[0] - b[0])
      .map(([seq, at]) => ({ checkpoint_seq_to: seq, attested_at: at.toISOString() })),
  };
}

/** Human-readable report. Never prints a reassuring word unless verdict is clean. */
export function formatReport(r: VerifyReport, dir: string): string {
  const lines: string[] = [];
  lines.push(`orisan-rec verify ${dir}`);
  lines.push(
    `  events: ${r.events}  checkpoints: ${r.checkpoints}  anchors verified: ${r.anchored}`
    + (r.prunedEvents > 0 ? `  pruned: ${r.prunedEvents}` : ''),
  );
  lines.push('');

  if (r.opensslCommands.length > 0) {
    lines.push('  timestamp checks were delegated to openssl — re-run these yourself:');
    for (const c of r.opensslCommands) lines.push(`    ${c}`);
    lines.push('');
    if (r.attestedTimes.length > 0) {
      // "Verification: OK" alone hides a re-anchoring. A human re-running the
      // command above should be told what time to expect.
      lines.push('  attested times (openssl ts -reply -in <tsr> -text):');
      for (const a of r.attestedTimes) {
        lines.push(`    checkpoint ..${a.checkpoint_seq_to}  ${a.attested_at}`);
      }
      lines.push('');
    }
  }

  if (r.findings.length > 0) {
    for (const f of r.findings) {
      const where = f.seq !== undefined ? ` [seq ${f.seq}]`
        : f.checkpoint_seq_to !== undefined ? ` [checkpoint ..${f.checkpoint_seq_to}]` : '';
      lines.push(`  ${f.severity === 'tampered' ? 'TAMPERED' : 'CANNOT VERIFY'}${where} ${f.code}`);
      lines.push(`    ${f.message}`);
    }
    lines.push('');
  }

  if (r.verdict === 'clean') {
    lines.push('  CLEAN — chain intact, every checkpoint signed, every checkpoint anchored');
    lines.push('          and every anchor accepted by openssl against the supplied TSA CA.');
  } else if (r.verdict === 'tampered') {
    lines.push('  TAMPERED — see the findings above.');
  } else {
    lines.push('  CANNOT VERIFY — some check could not be completed. This is NOT a pass.');
    lines.push('                  Treat this log as unproven until the gaps above are closed.');
  }
  return `${lines.join('\n')}\n`;
}

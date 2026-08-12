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
import { join } from 'node:path';

import {
  PUBLIC_KEY_FILENAME,
  anchorDigest,
  readCheckpoints,
  verifyCheckpointChain,
  verifyCheckpointSignature,
  type SignedCheckpoint,
} from './checkpoint.js';
import { merkleRoot } from './merkle.js';
import { EventStore } from './store.js';
import { anchorPaths, readAnchor } from './tsa.js';
import type { RecordedEvent } from './schema.js';

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
  checkpoints: number;
  anchored: number;
  findings: Finding[];
  /** openssl invocations run, verbatim, so a reviewer can repeat them. */
  opensslCommands: string[];
}

export interface VerifyOptions {
  /** CA bundle for the TSA. Without it the anchor check cannot run → exit 2. */
  tsaCaFile?: string;
  /** Override the openssl binary. */
  opensslPath?: string;
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
  events: readonly RecordedEvent[],
): Finding | null {
  const inRange = events.filter((e) => e.seq >= cp.seq_from && e.seq <= cp.seq_to);

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

  const actual = merkleRoot(inRange.map((e) => e.hash));
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

export function verify(dir: string, opts: VerifyOptions = {}): VerifyReport {
  const findings: Finding[] = [];
  const opensslCommands: string[] = [];
  const openssl = opts.opensslPath ?? 'openssl';

  // ---- 1. the chain -------------------------------------------------------
  const { store, recovery } = EventStore.open(dir);
  if (recovery.truncatedPartialTail) {
    findings.push({
      severity: 'cannot_verify',
      code: 'partial_tail_discarded',
      message:
        `a ${recovery.bytesDiscarded}-byte partial line was discarded from ${recovery.segment}; ` +
        'the final event may be missing',
    });
  }
  const events = store.readAll();
  for (const b of store.verifyChainOnly()) {
    findings.push({
      severity: 'tampered',
      code: `chain_${b.reason}`,
      seq: b.seq,
      message: `chain break at seq ${b.seq}: ${b.reason} (expected ${b.expected}, got ${b.actual})`,
    });
  }

  // ---- 2. checkpoint signatures ------------------------------------------
  const checkpoints = readCheckpoints(dir);
  const pubPath = join(dir, PUBLIC_KEY_FILENAME);
  const pubPem = existsSync(pubPath) ? readFileSync(pubPath, 'utf8') : null;

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

    if (opts.skipOpenssl) {
      findings.push({
        severity: 'cannot_verify',
        code: 'tsa_check_skipped',
        checkpoint_seq_to: cp.seq_to,
        message: 'TSA signature check was skipped',
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
  const anchoredCheckpoints = checkpoints.filter((cp) => readAnchor(dir, cp.seq_to) !== null);
  for (const cp of anchoredCheckpoints) {
    const f = checkCheckpointAgainstEvents(cp, events);
    if (f) findings.push(f);
  }

  // ---- 5. head coverage ---------------------------------------------------
  // The highest anchored seq_to is compared against the ACTUAL head of the
  // event log. Previously this only produced a warning, and the "last anchored
  // seq" was derived from whatever checkpoints survived — so deleting the
  // newest checkpoint together with the events it covered moved the goalposts
  // and the truncation became invisible. Both halves are now failures.
  const lastAnchoredSeq = anchoredCheckpoints.length
    ? Math.max(...anchoredCheckpoints.map((c) => c.seq_to))
    : -1;
  const headSeq = events.length > 0 ? events[events.length - 1]!.seq : -1;

  if (headSeq > lastAnchoredSeq) {
    const uncommitted = events.filter((e) => e.seq > lastAnchoredSeq).length;
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

  const verdict = worst(findings);
  return {
    verdict,
    exitCode: exitCodeFor(verdict),
    events: events.length,
    checkpoints: checkpoints.length,
    anchored,
    findings,
    opensslCommands,
  };
}

/** Human-readable report. Never prints a reassuring word unless verdict is clean. */
export function formatReport(r: VerifyReport, dir: string): string {
  const lines: string[] = [];
  lines.push(`orisan-rec verify ${dir}`);
  lines.push(`  events: ${r.events}  checkpoints: ${r.checkpoints}  anchors verified: ${r.anchored}`);
  lines.push('');

  if (r.opensslCommands.length > 0) {
    lines.push('  timestamp checks were delegated to openssl — re-run these yourself:');
    for (const c of r.opensslCommands) lines.push(`    ${c}`);
    lines.push('');
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

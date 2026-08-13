/**
 * R4 — "Prove it".
 *
 * Runs the tamper demo on the USER'S OWN LOG, not a canned animation and not a
 * fixture. A recorded demo proves the demo was recorded; the only thing that
 * proves anything about your records is attacking your records.
 *
 * SAFETY: everything happens on a copy in a temp directory. The real log is
 * opened read-only, copied out, and never written to. If this file has a bug,
 * the worst case is a wasted temp directory. There is a test asserting the
 * source log is byte-identical afterwards.
 *
 * Two attacks, deliberately, because they have different answers and the
 * difference IS the security model:
 *
 *   EDIT   change one recorded action in place. Always caught, with or without
 *          a witness, because the record stops matching its own fingerprint.
 *   DELETE remove the end of the log along with the summary covering it. Caught
 *          ONLY if a witness is configured. Without one this comes back "not
 *          detected", and saying so is the point — it is the same caveat the
 *          grey banner gives, demonstrated rather than asserted.
 */

import { cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { readCheckpoints } from './checkpoint.js';
import { EventStore, listSegments, segmentName } from './store.js';
import { verify, type VerifyOptions, type VerifyReport } from './verify.js';

export interface ProofStep {
  /** Short label for the UI. */
  title: string;
  /** What we did, in plain English. */
  did: string;
  /** What came back. */
  result: string;
  /** Did the tool notice? */
  detected: boolean | null;
  /** Machine-readable finding codes, for the detail view. */
  codes: string[];
}

export interface ProofRun {
  attack: 'edit' | 'delete_tail';
  title: string;
  /** What this attack is, without jargon. */
  premise: string;
  steps: ProofStep[];
  /** The bottom line, in one sentence. */
  verdict: string;
  detected: boolean;
}

export interface ProveResult {
  ranAt: string;
  /** Events in the real log at the time of the run. */
  events: number;
  checkpoints: number;
  witnessConfigured: boolean;
  baseline: { verdict: string; exitCode: number };
  runs: ProofRun[];
  /** True if the source log is byte-identical to how we found it. */
  sourceUntouched: boolean;
}

function snapshotOf(dir: string): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (d: string, prefix: string): void => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      const full = join(d, entry.name);
      if (entry.isDirectory()) walk(full, rel);
      else if (entry.isFile()) out.set(rel, readFileSync(full).toString('base64'));
    }
  };
  walk(dir, '');
  return out;
}

function sameSnapshot(a: Map<string, string>, b: Map<string, string>): boolean {
  if (a.size !== b.size) return false;
  for (const [k, v] of a) if (b.get(k) !== v) return false;
  return true;
}

function summarise(r: VerifyReport): { result: string; codes: string[] } {
  const codes = r.findings.map((f) => f.code);
  if (r.verdict === 'tampered') {
    const worst = r.findings.find((f) => f.severity === 'tampered');
    return { result: `Detected — ${worst?.message ?? 'a check failed'}`, codes };
  }
  if (r.verdict === 'clean') return { result: 'No problem found', codes };
  return { result: 'Could not complete every check', codes };
}

/** Chain-only check: what a naive tool would report. */
function chainOnly(dir: string): { intact: boolean; detail: string } {
  const breaks = EventStore.open(dir, { readOnly: true }).store.verifyChainOnly();
  return breaks.length === 0
    ? { intact: true, detail: 'reports the records as consistent' }
    : { intact: false, detail: `breaks at record ${breaks[0]!.seq}` };
}

export interface ProveOptions extends VerifyOptions {
  /** Injected so a caller can supply an already-fetched witness head. */
  witnessFor?: (copyDir: string) => VerifyOptions;
}

/**
 * Run both attacks against a copy of `dir` and report what happened.
 * Never modifies `dir`.
 */
export function prove(dir: string, opts: ProveOptions = {}): ProveResult {
  const before = snapshotOf(dir);
  const baseOpts: VerifyOptions = { ...opts };
  delete (baseOpts as { witnessFor?: unknown }).witnessFor;

  const baselineReport = verify(dir, baseOpts);
  const witnessConfigured = opts.witnessService !== undefined || opts.witnessFile !== undefined;
  const events = EventStore.open(dir, { readOnly: true }).store.readAll();
  const checkpoints = readCheckpoints(dir);

  const runs: ProofRun[] = [];
  const workspaces: string[] = [];

  try {
    // ---- attack 1: edit one recorded action -------------------------------
    {
      const copy = mkdtempSync(join(tmpdir(), 'orisan-prove-edit-'));
      workspaces.push(copy);
      cpSync(dir, copy, { recursive: true });

      const steps: ProofStep[] = [];
      // Prefer an action with a visible outcome; that makes the edit legible in the UI.
      const target = events.find((e) => e.outcome !== null) ?? events[0];

      if (!target) {
        steps.push({
          title: 'Nothing to edit', did: 'Looked for a recorded action to change.',
          result: 'This log has no actions yet.', detected: null, codes: [],
        });
        runs.push({
          attack: 'edit', title: 'Change one recorded action',
          premise: 'Someone edits an action after the fact to make it look harmless.',
          steps, verdict: 'Record something first, then run this again.', detected: false,
        });
      } else {
        const segFile = listSegments(copy)[0] ?? segmentName(0);
        const path = join(copy, segFile);
        const lines = readFileSync(path, 'utf8').trim().split('\n');
        const idx = lines.findIndex((l) => (JSON.parse(l) as { seq: number }).seq === target.seq);
        const doc = JSON.parse(lines[idx]!) as Record<string, unknown>;
        const wasOutcome = String(doc['outcome'] ?? '');
        doc['outcome'] = 'ok (edited by the Prove it demo)';
        lines[idx] = JSON.stringify(doc);
        writeFileSync(path, `${lines.join('\n')}\n`);

        steps.push({
          title: 'Edit an action',
          did: `Changed the result of action ${target.seq} from "${wasOutcome || 'nothing'}" to "ok (edited by the Prove it demo)" — exactly what someone covering their tracks would do.`,
          result: 'Done, on the copy.', detected: null, codes: [],
        });

        const report = verify(copy, opts.witnessFor ? opts.witnessFor(copy) : baseOpts);
        const s = summarise(report);
        steps.push({
          title: 'Check the copy',
          did: 'Ran the same check the banner runs.',
          result: s.result, detected: report.verdict === 'tampered', codes: s.codes,
        });

        const detected = report.verdict === 'tampered';
        runs.push({
          attack: 'edit',
          title: 'Change one recorded action',
          premise: 'Someone edits an action after the fact to make it look harmless.',
          steps,
          verdict: detected
            ? `Caught, and it names record ${target.seq} specifically. Editing a record breaks the fingerprint taken when it was written, and no amount of tidying up puts it back.`
            : 'Not caught. That is a bug — please report it.',
          detected,
        });
      }
    }

    // ---- attack 2: delete the end of the log ------------------------------
    {
      const copy = mkdtempSync(join(tmpdir(), 'orisan-prove-del-'));
      workspaces.push(copy);
      cpSync(dir, copy, { recursive: true });

      const steps: ProofStep[] = [];
      const cps = readCheckpoints(copy);

      if (events.length < 2 || cps.length === 0) {
        steps.push({
          title: 'Not enough to delete',
          did: 'Looked for a summary covering the end of the log.',
          result: 'This log needs at least one summary before this attack means anything.',
          detected: null, codes: [],
        });
        runs.push({
          attack: 'delete_tail', title: 'Delete the end of the log',
          premise: 'Someone deletes the last few actions along with the summary that covered them.',
          steps, verdict: 'Make a summary first (Evidence → the log needs a checkpoint), then run this again.',
          detected: false,
        });
      } else {
        const last = cps[cps.length - 1]!;
        const keep = events.filter((e) => e.seq < last.seq_from);
        const segFile = listSegments(copy)[0] ?? segmentName(0);
        for (const f of listSegments(copy)) rmSync(join(copy, f), { force: true });
        writeFileSync(join(copy, segFile), keep.map((e) => `${JSON.stringify(e)}\n`).join(''));

        const remaining = readFileSync(join(copy, 'checkpoints.jsonl'), 'utf8').trim().split('\n').slice(0, -1);
        writeFileSync(join(copy, 'checkpoints.jsonl'), remaining.length ? `${remaining.join('\n')}\n` : '');
        for (const d of ['anchors', 'receipts']) {
          const p = join(copy, d);
          if (!existsSync(p)) continue;
          const files = readdirSync(p).sort();
          const victim = files[files.length - 1];
          const victim2 = files[files.length - 2];
          for (const v of [victim, victim2]) if (v) rmSync(join(p, v), { force: true });
        }

        const removed = events.length - keep.length;
        steps.push({
          title: 'Delete the ending',
          did: `Deleted the last ${removed} action(s), the summary that covered them, and its outside timestamp — everything a careful person would remember to remove.`,
          result: 'Done, on the copy.', detected: null, codes: [],
        });

        const naive = chainOnly(copy);
        steps.push({
          title: 'What a simple check sees',
          did: 'Checked only whether the remaining records are consistent with each other.',
          result: `Nothing wrong — it ${naive.detail}. What is left is a shorter log that looks perfectly normal.`,
          detected: false, codes: [],
        });

        const report = verify(copy, opts.witnessFor ? opts.witnessFor(copy) : baseOpts);
        const s = summarise(report);
        const detected = report.verdict === 'tampered';
        steps.push({
          title: 'What the full check sees',
          did: 'Ran the same check the banner runs, including asking the witness what it remembers.',
          result: s.result, detected, codes: s.codes,
        });

        runs.push({
          attack: 'delete_tail',
          title: 'Delete the end of the log',
          premise: 'Someone deletes the last few actions along with the summary that covered them.',
          steps,
          verdict: detected
            ? 'Caught. The witness still remembers the summary that is no longer here, and a missing memory cannot be deleted from your machine.'
            : 'Not caught — and this is the honest answer, not a failure of the demo. Nothing inside a log can show you records that were deleted from the end, because what remains is genuinely consistent. This is exactly what the grey banner means. Set up a witness and run this again: it turns into "caught".',
          detected,
        });
      }
    }
  } finally {
    for (const w of workspaces) rmSync(w, { recursive: true, force: true });
  }

  return {
    ranAt: new Date().toISOString(),
    events: events.length,
    checkpoints: checkpoints.length,
    witnessConfigured,
    baseline: { verdict: baselineReport.verdict, exitCode: baselineReport.exitCode },
    runs,
    sourceUntouched: sameSnapshot(before, snapshotOf(dir)),
  };
}

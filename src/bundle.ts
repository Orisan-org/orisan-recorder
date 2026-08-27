/**
 * R2.3 — the evidence bundle.
 *
 * Everything a third party needs to check this log on a machine that has never
 * heard of us: the events, the checkpoints, the anchors, the public key, and
 * instructions that lean on openssl rather than on our binary.
 *
 * The signing PRIVATE key is never included. Neither are payload blobs or the
 * key that opens them — a bundle proves what happened, it does not hand over
 * the contents.
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import { CHECKPOINTS_FILENAME, PUBLIC_KEY_FILENAME } from './checkpoint.js';
import { ANCHOR_DIRNAME } from './tsa.js';
import { listSegments } from './store.js';
import { makeZip, type ZipEntry } from './zip.js';
import type { VerifyReport } from './verify.js';

/**
 * The auditor's README: the first thing someone outside the company opens.
 *
 * Written for a competent person who has never seen this product and owes us
 * no benefit of the doubt. It leads with what the bundle CANNOT tell them,
 * because that is the part that decides whether the rest is worth reading.
 *
 * No backticks in the body: this is a TypeScript template literal, and code
 * fences here have a habit of becoming a syntax error nobody notices.
 */
export const AUDITOR_README = `# What you have been sent, and what it is worth

Someone has handed you records claiming to show what an AI agent did. You do
not have to trust them, and you do not have to trust the tool that produced
this. Below is how to check it yourself and - more usefully - what it cannot
tell you no matter how well it checks out.

## Read this first: three things this cannot prove

**1. That everything the agent did is in here.** These records show what
reached the recorder. If an agent was never connected to it, nothing here would
know that agent existed. No amount of cryptography fixes that; it is a question
about how recording was set up, not about the files you are holding.

**2. That nothing was deleted from the end - unless a witness was used.** A log
can show its own records have not been edited. It cannot show that records were
not removed from the end, because what remains is genuinely consistent. The fix
is an outside service that keeps its own note of what the log contained. If
there is no witness, completeness was never established, and the operator could
have stopped recording at a convenient moment.

**3. That what the agent did was correct or authorised.** These are records of
what happened. Whether it should have happened is your judgement, not the
tool's.

## What it can prove, and how to check without our software

Everything below uses openssl, which almost certainly ships with your machine.
None of it runs our code.

### The records have not been edited

Each record carries a short code calculated from its own contents and from the
code of the record before it. Change one character anywhere and every code from
that point on stops matching. Recalculating them all is possible for whoever
holds the files - which is exactly why the next two checks exist.

### Batches were signed at the time

checkpoints.jsonl holds one line per batch of records, each signed with the key
in signing.pub.pem. Editing a batch invalidates its signature, and only the
holder of the matching private key can produce a new one. That private key is
deliberately not in this bundle.

### Batches were timestamped by someone with no stake in them

For each file in anchors/, the .json names a code and the .tsr is a timestamp
from an outside authority covering it:

    openssl ts -verify -digest <the digest from the .json> \
      -in anchors/<n>.tsr -CAfile <that authority's certificate>

Expect "Verification: OK". To see the time it attests:

    openssl ts -reply -in anchors/<n>.tsr -text | grep "Time stamp"

**Compare that time against the newest record in the batch.** A stamp issued
long after the actions it covers proves when someone asked for a stamp, not
when the actions happened. That is the most useful check in this file and it
takes ten seconds.

## Questions worth asking the operator

- Was a witness used? If not, why not?
- Where is the signing key kept? If it sits beside these records, whoever can
  edit them can also re-sign them.
- What would have happened to an agent that was never connected to the recorder?
- Does verify-report.json say clean? If it says cannot_verify, that is not a
  pass - it means a check could not be completed, and the report says which.

## If something does not check out

A failed check is a fact, not an accusation. A botched file copy and a
deliberate edit look identical from here. Report what failed and let someone
establish why.
`;

/** What a bundle turned out to contain, so its instructions can match it. */
export interface BundleContents {
  segments: string[];
  checkpoints: boolean;
  publicKey: boolean;
  anchors: string[];
  report: boolean;
}

/**
 * Build VERIFY.md from what this bundle actually holds.
 *
 * It used to be a constant. A constant cannot be right about a variable thing:
 * an unanchored log ships no anchors/ directory at all, and the fixed text
 * still listed anchors/*.tsr under "what is here" and spent a numbered section
 * telling the reader to verify them. An auditor following instructions to files
 * that are not there learns to distrust the instructions, which is the opposite
 * of what this file is for.
 */
export function verifyInstructions(c: BundleContents): string {
  const here: string[] = [];
  if (c.segments.length > 0) {
    here.push(`    ${(c.segments.length === 1 ? c.segments[0]! : 'events-*.jsonl').padEnd(19)} the append-only event log; one JSON object per line`);
  }
  if (c.checkpoints) here.push('    checkpoints.jsonl   signed checkpoints, each committing to a range of events');
  if (c.anchors.length > 0) {
    here.push('    anchors/*.tsr       RFC 3161 timestamp tokens, one per anchored checkpoint');
    here.push('    anchors/*.json      which digest each token covers');
  }
  if (c.publicKey) here.push('    signing.pub.pem     the Ed25519 public key the checkpoints are signed with');
  if (c.report) here.push('    verify-report.json  what our verifier said when this bundle was produced');

  const tokens = c.anchors.filter((f) => f.endsWith('.tsr')).length;
  const tsaSection = c.anchors.length > 0
    ? `## 2. Check a timestamp yourself

This bundle contains ${tokens === 1 ? 'one timestamp token' : `${tokens} timestamp tokens`}.
For each, read the digest from the .json and run:

    openssl ts -verify -digest <digest> -in anchors/<n>.tsr -CAfile <tsa-ca.pem>

You need the CA of the timestamp authority named in the anchor's tsa_url. Get it
from that authority, not from us. Expect "Verification: OK". To see the attested
time:

    openssl ts -reply -in anchors/<n>.tsr -text | grep "Time stamp"

Compare that time against the newest event in the checkpoint's range. A token
issued long after the events it covers attests to a re-anchoring, not to when
those events happened.
`
    : `## 2. Timestamps: there are none in this bundle

**No checkpoint here has been anchored**, so there is no anchors/ directory and
nothing for openssl to check. Nothing in this bundle establishes when any of it
existed; the ordering and the signatures are all it can offer.

That is a real gap, not a formality. Without an external timestamp, the whole
history could have been produced at any time, including after the fact. Ask
whoever sent you this bundle to run \`orisan-rec anchor\` and export again.
`;

  const sigSection = c.checkpoints && c.publicKey
    ? `## 3. Check the signatures

Each line of checkpoints.jsonl is an object with a "signature" field. The signed
payload is the canonical JSON of the object with "signature" removed, keys
sorted recursively, no whitespace. Verify with Ed25519 and signing.pub.pem.
`
    : `## 3. Signatures: not checkable from this bundle

${c.checkpoints ? 'signing.pub.pem is missing' : 'checkpoints.jsonl is missing'}, so there is nothing here to verify
signatures against. Without both files the events are an ordered list and
nothing more. Ask the sender for a complete export.
`;

  return `# Verifying this bundle

You do not need our software to check this, and you should not take our word
for any of it.

## 1. What is here

${here.join('\n')}

The signing private key is NOT here, and neither are payload blobs.
${c.anchors.length > 0 ? '' : '\nThere is no anchors/ directory: nothing in this log has been timestamped.\n'}
${tsaSection}
${sigSection}
## 4. What this bundle cannot tell you

- Whether every action reached the recorder at all. Nothing in a log can show
  an event that was never written.
- Whether the tail was truncated, unless you also hold witness records from
  outside the operator's control. A log with its trailing events and their
  checkpoints removed together still looks internally consistent.
${c.report
    ? '\nRead verify-report.json for what our own verifier concluded, including any\n"cannot verify" findings.\n'
    : '\nThis bundle carries no verify-report.json, so it does not include our own\nverifier\'s conclusion. Run `orisan-rec verify` against the log it came from,\nor ask the sender for a bundle exported with one.\n'}
A cannot-verify result is not a pass. Whatever tool you use, treat "I could not
check" as unproven rather than as clean.
`;
}

/** Kept for callers that only need the invariant wording, tests included. */
export const VERIFY_INSTRUCTIONS = verifyInstructions({
  segments: [], checkpoints: false, publicKey: false, anchors: [], report: false,
});

export interface BundleOptions {
  /** Include the verifier's own report. */
  report?: VerifyReport;
  now?: Date;
}

export function buildEvidenceBundle(dir: string, opts: BundleOptions = {}): Buffer {
  const entries: ZipEntry[] = [];
  const contents: BundleContents = {
    segments: [], checkpoints: false, publicKey: false, anchors: [], report: Boolean(opts.report),
  };
  const add = (path: string, abs: string): boolean => {
    if (!existsSync(abs)) return false;
    entries.push({ path, data: readFileSync(abs) });
    return true;
  };

  for (const seg of listSegments(dir)) { if (add(seg, join(dir, seg))) contents.segments.push(seg); }
  contents.checkpoints = add(CHECKPOINTS_FILENAME, join(dir, CHECKPOINTS_FILENAME));
  contents.publicKey = add(PUBLIC_KEY_FILENAME, join(dir, PUBLIC_KEY_FILENAME));

  const anchorDir = join(dir, ANCHOR_DIRNAME);
  if (existsSync(anchorDir)) {
    for (const f of readdirSync(anchorDir).sort()) {
      if (add(`${ANCHOR_DIRNAME}/${f}`, join(anchorDir, f))) contents.anchors.push(f);
    }
  }

  // README first, in intent as well as alphabetically: it is the file that
  // tells a stranger what the rest is worth.
  entries.push({ path: 'AUDITOR-README.md', data: Buffer.from(AUDITOR_README, 'utf8') });
  entries.push({ path: 'VERIFY.md', data: Buffer.from(verifyInstructions(contents), 'utf8') });
  if (opts.report) {
    entries.push({
      path: 'verify-report.json',
      data: Buffer.from(`${JSON.stringify(opts.report, null, 2)}\n`, 'utf8'),
    });
  }

  return makeZip(entries, opts.now ?? new Date());
}

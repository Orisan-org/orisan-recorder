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

export const VERIFY_INSTRUCTIONS = `# Verifying this bundle

You do not need our software to check the timestamps, and you should not take
our word for them.

## 1. What is here

    events-*.jsonl      the append-only event log; one JSON object per line
    checkpoints.jsonl   signed checkpoints, each committing to a range of events
    anchors/*.tsr       RFC 3161 timestamp tokens, one per checkpoint
    anchors/*.json      which digest each token covers
    signing.pub.pem     the Ed25519 public key the checkpoints are signed with
    verify-report.json  what our verifier said when this bundle was produced

The signing private key is NOT here, and neither are payload blobs.

## 2. Check a timestamp yourself

For each anchor, read the digest from the .json and run:

    openssl ts -verify -digest <digest> -in anchors/<n>.tsr -CAfile <tsa-ca.pem>

You need the CA of the timestamp authority named in the anchor's tsa_url.
Expect "Verification: OK". To see the attested time:

    openssl ts -reply -in anchors/<n>.tsr -text | grep "Time stamp"

Compare that time against the newest event in the checkpoint's range. A token
issued long after the events it covers attests to a re-anchoring, not to when
those events happened.

## 3. Check the signatures

Each line of checkpoints.jsonl is an object with a "signature" field. The signed
payload is the canonical JSON of the object with "signature" removed, keys
sorted recursively, no whitespace. Verify with Ed25519 and signing.pub.pem.

## 4. What this bundle cannot tell you

- Whether every action reached the recorder at all. Nothing in a log can show
  an event that was never written.
- Whether the tail was truncated, unless you also hold witness records from
  outside the operator's control. A log with its trailing events and their
  checkpoints removed together still looks internally consistent.

Read verify-report.json for what our own verifier concluded, including any
"cannot verify" findings. A cannot-verify result is not a pass.
`;

export interface BundleOptions {
  /** Include the verifier's own report. */
  report?: VerifyReport;
  now?: Date;
}

export function buildEvidenceBundle(dir: string, opts: BundleOptions = {}): Buffer {
  const entries: ZipEntry[] = [];
  const add = (path: string, abs: string): void => {
    if (existsSync(abs)) entries.push({ path, data: readFileSync(abs) });
  };

  for (const seg of listSegments(dir)) add(seg, join(dir, seg));
  add(CHECKPOINTS_FILENAME, join(dir, CHECKPOINTS_FILENAME));
  add(PUBLIC_KEY_FILENAME, join(dir, PUBLIC_KEY_FILENAME));

  const anchorDir = join(dir, ANCHOR_DIRNAME);
  if (existsSync(anchorDir)) {
    for (const f of readdirSync(anchorDir).sort()) {
      add(`${ANCHOR_DIRNAME}/${f}`, join(anchorDir, f));
    }
  }

  // README first, in intent as well as alphabetically: it is the file that
  // tells a stranger what the rest is worth.
  entries.push({ path: 'AUDITOR-README.md', data: Buffer.from(AUDITOR_README, 'utf8') });
  entries.push({ path: 'VERIFY.md', data: Buffer.from(VERIFY_INSTRUCTIONS, 'utf8') });
  if (opts.report) {
    entries.push({
      path: 'verify-report.json',
      data: Buffer.from(`${JSON.stringify(opts.report, null, 2)}\n`, 'utf8'),
    });
  }

  return makeZip(entries, opts.now ?? new Date());
}

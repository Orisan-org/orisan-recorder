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

  entries.push({ path: 'VERIFY.md', data: Buffer.from(VERIFY_INSTRUCTIONS, 'utf8') });
  if (opts.report) {
    entries.push({
      path: 'verify-report.json',
      data: Buffer.from(`${JSON.stringify(opts.report, null, 2)}\n`, 'utf8'),
    });
  }

  return makeZip(entries, opts.now ?? new Date());
}

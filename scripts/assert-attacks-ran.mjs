/**
 * Fail unless every confirmed attack actually EXECUTED.
 *
 * The README says every attack in SECURITY-REVIEW-R1.md runs in CI
 * permanently. A green suite does not establish that: a skipped suite is
 * green, a renamed test is green, and a deleted test is greenest of all. The
 * claim is about execution, so it needs a check on execution.
 *
 * Each entry below is a confirmed finding from the security review, paired
 * with the test that must be seen to pass. Adding an attack to the review
 * without adding it here leaves the claim overstated, which is why the review
 * file is parsed rather than trusted: a C-number present there and absent here
 * fails this script.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..');

/** Confirmed review findings -> the test name that must pass. */
const REQUIRED = {
  C1: 'A1: tail truncation',
  C2: 'A2: delete an event, re-seal from genesis',
  C3: 'A3: poison pill',
  C4: 'A4: total erasure',
  C5: 'A5: hole',
  C6: 'a PATH shim cannot make a bad token verify',
  C7: 'duplicate checkpoint lines are rejected',
};

const FILES = ['test/attacks.test.ts', 'test/attacker.test.ts', 'test/hardening.test.ts'];

function fail(lines) {
  process.stderr.write(`\n${lines.join('\n')}\n\n`);
  process.exit(1);
}

// 1. The review's confirmed findings must all be represented here. If someone
//    documents a new attack and does not wire it in, the claim silently widens
//    past what CI proves.
const review = readFileSync(join(repo, 'SECURITY-REVIEW-R1.md'), 'utf8');
const documented = [...review.matchAll(/^### (C\d+)\s+—/gm)].map((m) => m[1]);
const missing = documented.filter((c) => !(c in REQUIRED));
if (missing.length > 0) {
  fail([
    `SECURITY-REVIEW-R1.md documents ${missing.join(', ')} with no entry in this script.`,
    'The README claims every attack in that file runs in CI. Add the mapping,',
    'or the claim covers something CI does not check.',
  ]);
}

// 2. Run them and read the reporter's own account of what happened.
let report;
try {
  const raw = execFileSync(
    'npx',
    ['vitest', 'run', '--reporter=json', ...FILES],
    { cwd: repo, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'inherit'] },
  );
  report = JSON.parse(raw.slice(raw.indexOf('{')));
} catch (e) {
  fail(['The attack suites did not complete.', String(e.message ?? e).slice(0, 600)]);
}

const results = (report.testResults ?? []).flatMap((f) => f.assertionResults ?? []);
if (results.length === 0) fail(['No tests were reported. The attack suites did not run at all.']);

const problems = [];
for (const [id, needle] of Object.entries(REQUIRED)) {
  const hits = results.filter((r) => (r.fullName ?? r.title ?? '').includes(needle));
  if (hits.length === 0) {
    problems.push(`${id}: no test matching "${needle}" — renamed or deleted`);
  } else if (!hits.some((r) => r.status === 'passed')) {
    const states = [...new Set(hits.map((r) => r.status))].join(', ');
    problems.push(`${id}: "${needle}" did not pass — status ${states}`);
  }
}

const skipped = results.filter((r) => r.status === 'skipped' || r.status === 'pending');
if (skipped.length > 0) {
  problems.push(
    `${skipped.length} test(s) in the attack suites were SKIPPED: ` +
      skipped.slice(0, 5).map((r) => r.fullName ?? r.title).join('; '),
  );
}

if (problems.length > 0) {
  fail([
    'The attack tests did not all run and pass.',
    'README states every attack in SECURITY-REVIEW-R1.md runs in CI permanently.',
    '',
    ...problems.map((p) => `  ${p}`),
  ]);
}

process.stdout.write(
  `\nAll ${Object.keys(REQUIRED).length} confirmed attacks ran and passed ` +
    `(${results.length} tests across ${FILES.length} files, 0 skipped).\n`,
);

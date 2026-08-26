/**
 * Fail unless W1-W5 actually EXECUTED against a real witness service.
 *
 * The sibling of scripts/assert-attacks-ran.mjs, and it exists for the same
 * reason: a skipped suite is green. While the witness lived in a private
 * repository these suites skipped in CI, and the README said so. Now that CI
 * checks the service out, "W1-W5 run in CI" is a claim about execution, so it
 * is checked on execution rather than inferred from an exit code.
 *
 * If the witness is genuinely unavailable this script FAILS. That is the
 * difference from the old arrangement: a missing witness is no longer a quiet
 * skip, it is a broken build.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..');
const FILE = 'test/witness-attacks.test.ts';

/** The witness attacks -> the suite name that must be seen to pass. */
const REQUIRED = {
  W1: 'W1: local truncation',
  W2: 'W2: re-seal from genesis and try to re-register',
  W3: 'W3: a substituted witness',
  W4: 'W4: the witness is offline',
  W5: 'W5: a forged head',
};

function fail(lines) {
  process.stderr.write(`\n${lines.join('\n')}\n\n`);
  process.exit(1);
}

// 1. A suite added to the test file but not mapped here would run unchecked,
//    so the file is parsed rather than trusted. This is the same guard the
//    attack script applies to SECURITY-REVIEW-R1.md, pointed at the source.
const src = readFileSync(join(repo, FILE), 'utf8');
const declared = [...src.matchAll(/witnessSuite\(\s*'(W\d+)[^']*'/g)].map((m) => m[1]);
const unmapped = [...new Set(declared)].filter((w) => !(w in REQUIRED));
if (unmapped.length > 0) {
  fail([
    `${FILE} declares ${unmapped.join(', ')} with no entry in this script.`,
    'Add the mapping, or CI reports a pass over a suite it never checked.',
  ]);
}

// 2. Run them and read the reporter's own account of what happened.
let report;
try {
  const raw = execFileSync(
    'npx',
    ['vitest', 'run', '--reporter=json', FILE],
    { cwd: repo, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'inherit'] },
  );
  report = JSON.parse(raw.slice(raw.indexOf('{')));
} catch (e) {
  fail(['The witness suites did not complete.', String(e.message ?? e).slice(0, 600)]);
}

const results = (report.testResults ?? []).flatMap((f) => f.assertionResults ?? []);
if (results.length === 0) fail(['No tests were reported. The witness suites did not run at all.']);

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

// 3. The whole point. A skip here used to be acceptable; it is not any more.
const skipped = results.filter((r) => r.status === 'skipped' || r.status === 'pending');
if (skipped.length > 0) {
  problems.push(
    `${skipped.length} witness test(s) were SKIPPED, which means no witness service ` +
      'was reachable. ORISAN_WITNESS_SRC must point at a checkout of orisan-witness.',
  );
}

if (problems.length > 0) {
  fail([
    'W1-W5 did not all run and pass.',
    'The README states they run in CI against a real witness service.',
    '',
    ...problems.map((p) => `  ${p}`),
  ]);
}

process.stdout.write(
  `\nAll ${Object.keys(REQUIRED).length} witness attacks ran and passed ` +
    `(${results.length} tests, 0 skipped).\n`,
);

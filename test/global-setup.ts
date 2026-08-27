/**
 * Say once, up front, which checks cannot run in this environment.
 *
 * The witness suites need a sibling repository that a public clone does not
 * have. They skip when it is absent, and vitest counts the skips — but a count
 * is easy to read past, and these are the tests that prove the product's
 * central claim. So the reason is stated in words before anything runs.
 *
 * globalSetup, not setupFiles: setupFiles runs once per test FILE, which
 * printed this banner thirty times.
 *
 * It also stays quiet when this run contains none of the affected suites.
 * scripts/assert-attacks-ran.mjs runs only the three attack files, and those
 * need no witness — announcing a skip there described something that was not
 * happening, and printed an alarm across an entirely green run. A warning that
 * cries wolf is worse than no warning: it teaches the reader to skim past the
 * place a real one would appear.
 */
import { WITNESS_SKIP_REASON, witnessAvailable } from './fixtures/witness-fixture.js';

/** Suites that skip without a witness, by the fragment that identifies them. */
const AFFECTED = ['witness-attacks', 'repoint', 'throttle', 'showcase'];

/**
 * The suites this run will actually skip.
 *
 * vitest does not hand globalSetup its CLI file filters — the context carries
 * `provide` and `config`, and config only has the configured `include` — so the
 * filters are read from argv. Anything that does not look like a test path is
 * ignored, which means a run with no file filter (`npm test`) is correctly
 * treated as covering everything.
 */
function affectedInThisRun(argv: string[]): string[] {
  const filters = argv.filter((a) => !a.startsWith('-') && /(^|\/)test\/|\.test\.ts$/.test(a));
  if (filters.length === 0) return AFFECTED;           // whole suite
  return AFFECTED.filter((name) => filters.some((f) => f.includes(name)));
}

export default function globalSetup(): void {
  if (witnessAvailable) return;
  const affected = affectedInThisRun(process.argv.slice(2));
  if (affected.length === 0) return;                   // nothing here needs one

  const line = '─'.repeat(74);
  process.stderr.write(
    `\n${line}\n` +
      'SKIPPING the witness suites. They are reported as skipped, not passed.\n' +
      `  reason:   ${WITNESS_SKIP_REASON}\n` +
      `  affected: ${affected.join(', ')}\n` +
      '  covering: truncation, fork and rug-pull detection — the checks that need\n' +
      '            a witness the operator does not control. Everything else runs.\n' +
      '  to run:   clone Orisan-org/orisan-witness to ../orisan-witness and npm\n' +
      '            install there, or set ORISAN_WITNESS_SRC to its src directory\n' +
      `${line}\n`,
  );
}

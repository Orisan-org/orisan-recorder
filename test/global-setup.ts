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
 */
import { WITNESS_SKIP_REASON, witnessAvailable } from './fixtures/witness-fixture.js';

export default function globalSetup(): void {
  if (witnessAvailable) return;
  const line = '─'.repeat(74);
  process.stderr.write(
    `\n${line}\n` +
      'SKIPPING the witness suites. They are reported as skipped, not passed.\n' +
      `  reason:   ${WITNESS_SKIP_REASON}\n` +
      '  affected: witness-attacks, repoint, throttle, showcase\n' +
      '  covering: truncation, fork and rug-pull detection — the checks that need\n' +
      '            a witness the operator does not control. Everything else runs.\n' +
      '  to run:   clone Orisan-org/orisan-witness to ../orisan-witness and npm\n' +
      '            install there, or set ORISAN_WITNESS_SRC to its src directory\n' +
      `${line}\n`,
  );
}

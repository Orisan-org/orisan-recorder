/**
 * `orisan-rec showcase` — the whole argument, start to finish, no typing.
 *
 * It runs the REAL commands as subprocesses. Nothing here reimplements a step
 * in-process and prints a plausible result: what you see on screen is what
 * executed, including the exit codes. If a step fails it fails on camera, and
 * the run ends in SHOWCASE FAILED rather than reading as a success.
 *
 * The point is the last three steps. A log is truncated, the chain-only check
 * calls it intact, and the full check catches it because a service outside
 * this machine still remembers the checkpoint that was deleted. Everything
 * before exists to make those three lines mean something.
 *
 * Defaults hit the real witness and the real timestamp authority, because a
 * demo against mocks proves nothing. Both are overridable so the test suite
 * runs the identical script offline.
 */

import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { readCheckpoints } from './checkpoint.js';
import { EventStore, listSegments } from './store.js';
import { witnessIsLoopback } from './verify.js';

export const DEFAULT_WITNESS_URL = 'https://witness.orisan.org';
export const DEFAULT_SHOWCASE_TSA_URL = 'https://freetsa.org/tsr';
export const DEFAULT_TSA_CA_URL = 'https://freetsa.org/files/cacert.pem';

export interface ShowcaseOptions {
  /** Where the demo log lives. A fresh temp directory by default. */
  dir?: string;
  witnessUrl?: string;
  tsaUrl?: string;
  /** Local CA file. Fetched from the authority if absent. */
  tsaCaFile?: string;
  /** Milliseconds between steps, so a recording is readable. 0 for tests. */
  pauseMs?: number;
  keep?: boolean;
  /** How to invoke the CLI: [command, ...leadingArgs]. */
  cli?: string[];
  /**
   * Name shown in the echoed command line. Defaults to `orisan-rec`, which is
   * what the binary is called once installed and is exactly the same entry
   * point being spawned — only the absolute interpreter path is elided, so a
   * recording is not three quarters filesystem noise. The arguments shown are
   * the arguments run, verbatim.
   */
  displayAs?: string;
  /** Drop colour, for tests and for piping to a file. */
  plain?: boolean;
  out?: (s: string) => void;
}

export interface StepResult { step: number; title: string; exitCode: number; ok: boolean }

export interface ShowcaseResult {
  dir: string;
  steps: StepResult[];
  /** True only when every step behaved as the script asserts it should. */
  ok: boolean;
  failures: string[];
}

/** Built from a char code so no literal escape bytes live in this source. */
const E = String.fromCharCode(27);
const C = {
  reset: `${E}[0m`, bold: `${E}[1m`, dim: `${E}[2m`,
  green: `${E}[32m`, red: `${E}[31m`, cyan: `${E}[36m`,
};
const PLAIN = { reset: '', bold: '', dim: '', green: '', red: '', cyan: '' };

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Run a command, streaming its output, and return the exit code. */
function run(cmd: string[], out: (s: string) => void): Promise<number> {
  return new Promise((resolve) => {
    const child = spawn(cmd[0]!, cmd.slice(1), { stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', (d: Buffer) => out(d.toString()));
    child.stderr.on('data', (d: Buffer) => out(d.toString()));
    child.on('error', (e) => { out(`  could not run: ${e.message}\n`); resolve(127); });
    child.on('close', (code) => resolve(code ?? 0));
  });
}

export async function runShowcase(opts: ShowcaseOptions = {}): Promise<ShowcaseResult> {
  const out = opts.out ?? ((s: string) => process.stdout.write(s));
  const p = opts.plain ? PLAIN : C;
  const pause = opts.pauseMs ?? 1600;
  const dir = opts.dir ?? mkdtempSync(join(tmpdir(), 'orisan-showcase-'));
  const witnessUrl = opts.witnessUrl ?? DEFAULT_WITNESS_URL;
  const tsaUrl = opts.tsaUrl ?? DEFAULT_SHOWCASE_TSA_URL;
  const cli = opts.cli ?? ['orisan-rec'];
  // Beside the log rather than in a temp path, so the echoed commands stay
  // short enough to read on a recording.
  const keyDir = `${dir}-key`;
  mkdirSync(keyDir, { recursive: true });
  const keyPath = join(keyDir, 'signing.key');
  const display = opts.displayAs ?? 'orisan-rec';

  const steps: StepResult[] = [];
  const failures: string[] = [];

  const heading = async (n: number, title: string, why: string): Promise<void> => {
    out(`\n${p.bold}${p.cyan}-- ${n}. ${title}${p.reset}\n`);
    out(`${p.dim}   ${why}${p.reset}\n\n`);
    await sleep(Math.min(pause, 900));
  };
  const shown = async (args: string[]): Promise<number> => {
    out(`${p.dim}$ ${[display, ...args].join(' ')}${p.reset}\n`);
    const code = await run([...cli, ...args], out);
    await sleep(pause);
    return code;
  };
  const record = (step: number, title: string, exitCode: number, expected: number): void => {
    const ok = exitCode === expected;
    steps.push({ step, title, exitCode, ok });
    if (!ok) failures.push(`step ${step} (${title}): expected exit ${expected}, got ${exitCode}`);
  };

  // A witness on this machine is one the operator can delete, so verify
  // refuses to count it and CLEAN is unreachable. That is correct, but a demo
  // that just returns 2 with no explanation looks broken. Say so up front and
  // expect the different result, rather than quietly failing at step 5.
  const localWitness = witnessIsLoopback(witnessUrl);
  const cleanExpected = localWitness ? 2 : 0;

  out(`\n${p.bold}Orisan Recorder -- showcase${p.reset}\n`);
  out(`${p.dim}Everything below runs for real: the witness at ${witnessUrl},${p.reset}\n`);
  out(`${p.dim}a real timestamp from ${new URL(tsaUrl).host}, and openssl doing the checking.${p.reset}\n`);
  if (localWitness) {
    out(`\n${p.bold}   Note: that witness runs on this machine.${p.reset}\n`);
    out(`${p.dim}   A witness the operator can delete is not outside their control, so step 5${p.reset}\n`);
    out(`${p.dim}   will report "cannot prove completeness" rather than CLEAN. Step 8 still${p.reset}\n`);
    out(`${p.dim}   catches the deletion. Point --witness at a hosted one for the full run.${p.reset}\n`);
  }
  await sleep(pause);

  // ---- 1. discovery -------------------------------------------------------
  await heading(1, 'What is on this machine',
    'Including agents nobody registered. This is the part no competitor does.');
  record(1, 'scan', await shown(['scan']), 0);

  // ---- 2. record ----------------------------------------------------------
  await heading(2, 'Record a session',
    'A fabricated session, labelled as such -- no real agent is being driven here.');
  record(2, 'record', await shown(['demo', dir, '--events', '18']), 0);

  // ---- 3. timeline --------------------------------------------------------
  await heading(3, 'What was recorded', 'Read back from the log on disk, not from memory.');
  const events = EventStore.open(dir, { readOnly: true }).store.readAll();
  for (const e of events.slice(0, 8)) {
    const flagged = e.kind === 'flag';
    out(`   ${p.dim}${e.ts.slice(11, 19)}${p.reset}  `
      + `${flagged ? p.red : ''}${e.kind.padEnd(14)}${e.target ?? ''}${flagged ? p.reset : ''}\n`);
  }
  if (events.length > 8) out(`   ${p.dim}... ${events.length - 8} more${p.reset}\n`);
  out(`\n   ${events.length} actions, ${events.filter((e) => e.kind === 'flag').length} flagged\n`);
  steps.push({ step: 3, title: 'timeline', exitCode: 0, ok: events.length > 0 });
  if (events.length === 0) failures.push('step 3 (timeline): no events were recorded');
  await sleep(pause);

  // ---- 4. commit it externally -------------------------------------------
  await heading(4, 'Commit it outside this machine',
    'A summary is signed, timestamped by an outside authority, and sent to the witness.');
  record(4, 'register', await shown(['witness', 'register', dir, '--url', witnessUrl, '--key', keyPath]), 0);
  record(4, 'checkpoint 1', await shown(['checkpoint', dir, '--key', keyPath]), 0);
  record(4, 'anchor 1', await shown(['anchor', dir, '--tsa', tsaUrl]), 0);
  record(4, 'submit 1', await shown(['witness', 'submit', dir, '--key', keyPath]), 0);

  // A second round, so the log has more than one committed batch. With a
  // single checkpoint, deleting "the tail" deletes the entire log — which
  // demonstrates nothing, because an empty log is obviously wrong. Two
  // batches means the truncated log is a plausible shorter one, which is the
  // whole difficulty the witness exists to solve.
  out(`\n${p.dim}   the agent keeps working, and a second batch is committed${p.reset}\n\n`);
  record(4, 'record more', await shown(['demo', dir, '--events', '14']), 0);
  record(4, 'checkpoint 2', await shown(['checkpoint', dir, '--key', keyPath]), 0);
  record(4, 'anchor 2', await shown(['anchor', dir, '--tsa', tsaUrl]), 0);
  record(4, 'submit 2', await shown(['witness', 'submit', dir, '--key', keyPath]), 0);

  // The CA comes from the authority, never from us.
  const caFile = opts.tsaCaFile ?? join(dir, 'tsa-ca.pem');
  if (!existsSync(caFile)) {
    out(`${p.dim}$ curl -o tsa-ca.pem ${DEFAULT_TSA_CA_URL}${p.reset}\n`);
    try {
      const res = await fetch(DEFAULT_TSA_CA_URL);
      writeFileSync(caFile, Buffer.from(await res.arrayBuffer()));
      out('   fetched the timestamp authority certificate\n');
    } catch (e) {
      out(`   ${p.red}could not fetch the CA: ${(e as Error).message}${p.reset}\n`);
      failures.push(`step 4 (tsa ca): ${(e as Error).message}`);
    }
    await sleep(pause);
  }

  // ---- 5. verify ----------------------------------------------------------
  await heading(5, 'Check it',
    'Chain, signatures, timestamps, and the witness. openssl checks the timestamp, not us.');
  const clean = await shown(['verify', dir, '--tsa-ca', caFile]);
  out(`   ${clean === cleanExpected ? p.green : p.red}exit ${clean}${p.reset}`
    + `${localWitness ? `   ${p.dim}<- 2, because the witness is on this machine${p.reset}` : ''}\n`);
  record(5, 'verify (clean)', clean, cleanExpected);
  await sleep(pause);

  // ---- 6. the attack ------------------------------------------------------
  await heading(6, 'Now delete the end of the log',
    'Actions, the summary covering them, its timestamp and its receipt.');
  const cps = readCheckpoints(dir);
  const last = cps[cps.length - 1];
  // Re-read: the second recording round added events after the step 3 snapshot.
  const onDisk = EventStore.open(dir, { readOnly: true }).store.readAll();
  if (!last || cps.length < 2) {
    failures.push('step 6 (truncate): needs at least two checkpoints to leave a plausible prefix');
    steps.push({ step: 6, title: 'truncate', exitCode: 1, ok: false });
  } else {
    const keep = onDisk.filter((e) => e.seq < last.seq_from);
    const segment = listSegments(dir)[0] ?? 'events-0000.jsonl';
    for (const f of listSegments(dir)) rmSync(join(dir, f), { force: true });
    writeFileSync(join(dir, segment), keep.map((e) => `${JSON.stringify(e)}\n`).join(''));
    const remaining = readFileSync(join(dir, 'checkpoints.jsonl'), 'utf8').trim().split('\n').slice(0, -1);
    writeFileSync(join(dir, 'checkpoints.jsonl'), remaining.length ? `${remaining.join('\n')}\n` : '');
    for (const sub of ['anchors', 'receipts']) {
      const path = join(dir, sub);
      if (!existsSync(path)) continue;
      for (const f of readdirSync(path).sort().slice(-2)) rmSync(join(path, f), { force: true });
    }
    out(`   ${p.red}deleted${p.reset} ${onDisk.length - keep.length} actions, `
      + 'one summary, its timestamp and its receipt\n');
    out(`   ${keep.length} actions remain, and they are internally consistent\n`);
    steps.push({ step: 6, title: 'truncate', exitCode: 0, ok: true });
  }
  await sleep(pause);

  // ---- 7. the naive check -------------------------------------------------
  await heading(7, 'What a simple integrity check sees',
    'Only whether the remaining records are consistent with each other.');
  const chain = await shown(['chain', dir]);
  out(`   ${chain === 0 ? p.green : p.red}exit ${chain}${p.reset}   `
    + `${p.dim}<- nothing wrong. This is all a log can say about itself.${p.reset}\n`);
  record(7, 'chain-only (fooled)', chain, 0);
  await sleep(pause);

  // ---- 8. the real check --------------------------------------------------
  await heading(8, 'What the full check sees',
    'The same log. This time it also asks the witness what it remembers.');
  const tampered = await shown(['verify', dir, '--tsa-ca', caFile]);
  out(`   ${tampered === 1 ? p.red : p.green}exit ${tampered}${p.reset}\n`);
  record(8, 'verify (tampered)', tampered, 1);
  await sleep(pause);

  // ---- 9. the point -------------------------------------------------------
  const ok = failures.length === 0;
  out(`\n${p.bold}-- 9.${p.reset}\n`);
  out(`${p.bold}   The log said it was fine. The witness said a checkpoint is missing.${p.reset}\n`);
  out(`${p.dim}   Deleting the end of a log leaves something that still looks consistent,${p.reset}\n`);
  out(`${p.dim}   which is why the check at step 7 returned 0. A record kept where the${p.reset}\n`);
  out(`${p.dim}   operator cannot reach it is what closes that gap.${p.reset}\n\n`);

  if (!ok) {
    out(`${p.red}${p.bold}   SHOWCASE FAILED${p.reset}\n`);
    for (const f of failures) out(`${p.red}     ${f}${p.reset}\n`);
    out('\n');
  }

  if (!opts.keep && !opts.dir) rmSync(dir, { recursive: true, force: true });
  rmSync(keyDir, { recursive: true, force: true });

  return { dir, steps, ok, failures };
}

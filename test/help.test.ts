/**
 * Issue #6 — --help on every command, and never a directory named `--help`.
 *
 * `orisan-rec demo --help` created a directory called `--help`, wrote 40 events
 * into it, and printed "wrote 40 events (1 flagged) to --help". The log
 * directory is positional and flags were not validated, so any mistyped flag
 * became a path and the command reported success.
 *
 * The CLI is spawned as a real process for each case, because the failure was
 * in argument handling before anything else ran.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFile } from 'node:child_process';
import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

const run = promisify(execFile);
const TSX = join(process.cwd(), 'node_modules', '.bin', 'tsx');
const CLI = join(process.cwd(), 'src', 'cli.ts');

/** Every command that takes a positional path, and one that takes none. */
const PATH_COMMANDS = ['demo', 'ui', 'tap', 'chain', 'checkpoint', 'anchor', 'verify', 'attach', 'detach'] as const;
const ALL_COMMANDS = [...PATH_COMMANDS, 'witness', 'scan', 'start', 'showcase'] as const;

/** Flag shapes a user plausibly types where a directory belongs. */
const FLAGGY = ['--help', '-h', '--events', '--verbose', '-x', '--dir'] as const;

let cwd: string;
beforeEach(() => { cwd = mkdtempSync(join(tmpdir(), 'orisan-help-')); });
afterEach(() => { rmSync(cwd, { recursive: true, force: true }); });

async function cli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await run(TSX, [CLI, ...args], { cwd, timeout: 30_000 });
    return { code: 0, stdout, stderr };
  } catch (e) {
    const err = e as { code?: number; stdout?: string; stderr?: string };
    return { code: err.code ?? 1, stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
  }
}

describe('--help works on every command', () => {
  for (const cmd of ALL_COMMANDS) {
    it(`${cmd} --help prints usage and exits 0`, async () => {
      const r = await cli([cmd, '--help']);
      expect(r.code, r.stderr).toBe(0);
      expect(r.stdout).toContain(`orisan-rec ${cmd === 'witness' ? 'witness register' : cmd}`);
      expect(r.stdout.length).toBeGreaterThan(40);
    }, 60_000);
  }

  it('-h is accepted as well as --help', async () => {
    const r = await cli(['verify', '-h']);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('cannot-verify');
  }, 60_000);

  it('help for verify states the exit code contract', async () => {
    const { stdout } = await cli(['verify', '--help']);
    expect(stdout).toContain('0  clean');
    expect(stdout).toContain('1  tampered');
    expect(stdout).toContain('2  cannot-verify');
    expect(stdout).toMatch(/NEVER a pass/);
  }, 60_000);

  it('bare orisan-rec still prints the overall usage', async () => {
    const r = await cli([]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('orisan-rec — recorder for AI agent actions');
  }, 60_000);
});

describe('no directory is created for a flag-looking argument', () => {
  for (const cmd of PATH_COMMANDS) {
    for (const flagArg of FLAGGY) {
      it(`${cmd} ${flagArg} creates nothing`, async () => {
        await cli([cmd, flagArg]);
        // The whole point: the working directory is untouched, whatever the
        // command decided to print or exit with.
        expect(readdirSync(cwd), `${cmd} ${flagArg} created something`).toEqual([]);
      }, 60_000);
    }
  }

  it('witness subcommands do not take a flag as their directory either', async () => {
    for (const flagArg of ['--help', '--url', '-x']) {
      await cli(['witness', 'submit', flagArg]);
      expect(readdirSync(cwd), `witness submit ${flagArg} created something`).toEqual([]);
    }
  }, 60_000);
});

describe('a flag where a directory belongs is an error, not a path', () => {
  it('demo --events (with the value missing) refuses instead of guessing', async () => {
    const r = await cli(['demo', '--events']);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('expected a directory, got the flag "--events"');
    expect(readdirSync(cwd)).toEqual([]);
  }, 60_000);

  it('the refusal shows that command\'s help, so the fix is on screen', async () => {
    const r = await cli(['verify', '--tsa-ca']);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('orisan-rec verify <dir>');
  }, 60_000);

  it('a real directory argument is still accepted', async () => {
    const r = await cli(['demo', 'real-dir', '--events', '5']);
    expect(r.code, r.stderr).toBe(0);
    expect(readdirSync(cwd)).toEqual(['real-dir']);
    expect(readdirSync(join(cwd, 'real-dir'))).toContain('events-0000.jsonl');
  }, 60_000);

  it('a directory whose name legitimately starts with a dash needs ./', async () => {
    // Not a regression: this is how every unix tool behaves, and the
    // alternative is the bug. `./-weird` works.
    const r = await cli(['demo', './-weird', '--events', '3']);
    expect(r.code, r.stderr).toBe(0);
    expect(readdirSync(cwd)).toEqual(['-weird']);
  }, 60_000);
});

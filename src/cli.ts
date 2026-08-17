#!/usr/bin/env node
/**
 * orisan-rec CLI.
 *
 * Exit codes for `verify` are the contract: 0 clean, 1 tampered,
 * 2 cannot-verify. Nothing may report 0 unless every check ran and passed.
 */

import { generateDemoSession } from './demo.js';
import { scan, serverCount } from './discover.js';
import { attach, detach, discardBackup } from './attach.js';
import { fileURLToPath } from 'node:url';
import { dirname as pathDirname, join as pathJoin } from 'node:path';
import { existsSync, writeFileSync } from 'node:fs';
import { EventIndex } from './index-db.js';
import { EventStore } from './store.js';
import { spawn } from 'node:child_process';
import { Recorder } from './recorder.js';
import { readCheckpoints } from './checkpoint.js';
import { DEFAULT_TSA_URL, drainAnchorQueue, pendingAnchors } from './tsa.js';
import { formatReport, verify } from './verify.js';
import { DEFAULT_PORT, startServer } from './server.js';
import { DEFAULT_TAP_PORT, startTap } from './tap.js';
import { defaultHome, prepareStart, setupSteps, startBanner } from './quickstart.js';
import { runShowcase } from './showcase.js';
import { generateKeyFile, loadKeyFile } from './payloads.js';
import {
  DRAIN_RETRY, fetchHead, pendingSubmissions, readWitnessConfig, registerLog, repointWitness,
  submitCheckpoint, WitnessKeyMismatch,
} from './witness-service.js';
import { generateSigningKey, loadSigningKey, signingKeyPath } from './checkpoint.js';

function usage(): string {
  return [
    'orisan-rec — recorder for AI agent actions',
    '',
    'Usage:',
    '  orisan-rec start                          set everything up and open the interface',
    '  orisan-rec showcase [--pause ms] [--keep] run the whole demo, start to finish',
    '  orisan-rec scan [--out <agents.json>]     find agents and MCP servers on this machine',
    '  orisan-rec attach <config> --log <dir>    route a config through the recorder',
    '  orisan-rec detach <config>                restore the original config exactly',
    '  orisan-rec demo <dir> [--events N] [--with-ui]  write a fabricated session',
    '  orisan-rec ui <dir> [--port N] [--payload-key <p>]   serve the local UI',
    '  orisan-rec tap <dir> --upstream <url>     record model calls through an HTTP tap',
    '        [--port N] [--payload-key <path>] [--key <signing>] [--no-context]',
    '  orisan-rec chain <dir>                    chain-integrity check only (NOT verify)',
    '  orisan-rec checkpoint <dir> [--key <p>]   cut a checkpoint over uncovered events',
    '  orisan-rec anchor <dir> [--tsa <url>]     anchor any unanchored checkpoints',
    '  orisan-rec witness register <dir> --url <witness>   register and PIN the witness key',
    '  orisan-rec witness submit <dir>           submit any unwitnessed checkpoints',
    '  orisan-rec witness repoint <dir> --url <new>  move a log to a new witness hostname',
    '  orisan-rec verify <dir> [--tsa-ca <pem>] [--witness <file>] [--tsa <url>]',
    '                                            full verification',
    '',
    'verify exit codes:  0 clean   1 tampered   2 cannot-verify',
    'A cannot-verify result is never a pass.',
    '',
  ].join('\n');
}

async function serveUi(dir: string, argv: string[]): Promise<number> {
  const portFlag = flag(argv, '--port');
  const port = portFlag !== undefined ? Number.parseInt(portFlag, 10) : DEFAULT_PORT;
  const runner = shimRunner();
  const { port: bound } = await startServer({
    logDir: dir,
    port,
    shimPath: runner.shimPath,
    nodePath: runner.nodePath,
    ...(flag(argv, '--key') !== undefined ? { signingKeyPath: flag(argv, '--key')! } : {}),
    ...(flag(argv, '--witness') !== undefined ? { witnessFile: flag(argv, '--witness')! } : {}),
    ...(flag(argv, '--tsa-ca') !== undefined ? { tsaCaFile: flag(argv, '--tsa-ca')! } : {}),
    // Without this the interface shows that context was captured and encrypted,
    // but cannot display it. That is the correct default: reading prompts
    // should take a deliberate act.
    ...(flag(argv, '--payload-key') !== undefined ? { payloadKeyPath: flag(argv, '--payload-key')! } : {}),
  });
  const url = `http://127.0.0.1:${bound}`;
  process.stdout.write(
    `UI on ${url}\n` +
    '  loopback only, no authentication — the binding is the access control\n' +
    '  Ctrl-C to stop\n',
  );
  try {
    const opener = process.platform === 'darwin' ? 'open' : 'xdg-open';
    spawn(opener, [url], { stdio: 'ignore', detached: true }).unref();
  } catch {
    // A browser that will not open is not a failure worth exiting for.
  }
  // Hold the process open for the server.
  await new Promise(() => undefined);
  return 0;
}

/**
 * How to launch the shim, as a config must record it.
 *
 * This has to be a runnable pair, not just a path. An earlier version wrote
 * `node .../src/shim-main.ts` into the user's config, which plain node cannot
 * execute — the unit tests passed because they injected tsx explicitly, and
 * only an end-to-end attach against a real config showed it. Prefer the built
 * JS; fall back to tsx over the source for a dev checkout.
 */
function shimRunner(): { nodePath: string; shimPath: string } {
  const here = pathDirname(fileURLToPath(import.meta.url));
  const repoRoot = here.endsWith('dist') ? pathJoin(here, '..') : pathJoin(here, '..');

  const built = pathJoin(repoRoot, 'dist', 'shim-main.js');
  if (existsSync(built)) return { nodePath: process.execPath, shimPath: built };

  const sameDirJs = pathJoin(here, 'shim-main.js');
  if (existsSync(sameDirJs)) return { nodePath: process.execPath, shimPath: sameDirJs };

  const tsx = pathJoin(repoRoot, 'node_modules', '.bin', 'tsx');
  const srcTs = pathJoin(here, 'shim-main.ts');
  if (existsSync(tsx) && existsSync(srcTs)) return { nodePath: tsx, shimPath: srcTs };

  throw new Error('cannot locate a runnable shim; run `npm run build` first');
}

function flag(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
}

/**
 * Issue #6 — per-command help, and no directory named `--help`.
 *
 * The log directory is a positional argument and flags were never validated,
 * so `orisan-rec demo --help` created a directory called `--help`, wrote 40
 * events into it and reported success. Two fixes: real help for every command,
 * and a refusal to treat a flag-looking argument as a path.
 */
const COMMAND_HELP: Record<string, string[]> = {
  start: [
    'orisan-rec start [--no-demo] [--port N]',
    '',
    'Set everything up and open the interface: creates ~/.orisan, generates the',
    'signing and payload keys if they are missing, writes a demo session unless',
    '--no-demo, and serves the UI on loopback.',
    '',
    '  --no-demo     do not write a fabricated session',
    '  --port N      UI port (default ' + String(DEFAULT_PORT) + ')',
  ],
  showcase: [
    'orisan-rec showcase [--dir <dir>] [--pause ms] [--keep] [--plain]',
    '',
    'Run the whole argument start to finish, no typing: discovery, a recorded',
    'session, a signed and externally timestamped batch, a CLEAN check, then the',
    'end of the log is deleted so the chain-only check is fooled and the full',
    'check catches it. Exits non-zero if any step misbehaves.',
    '',
    '  --dir <dir>      where to build the demo log (default: a temp directory)',
    '  --pause ms       pause between steps, for screen recording',
    '  --keep           do not delete the log afterwards',
    '  --plain          no colour',
    '  --witness <url>  witness to use (default: the hosted one)',
    '  --tsa <url>      timestamp authority',
    '  --tsa-ca <pem>   CA bundle for verifying the timestamp',
  ],
  scan: [
    'orisan-rec scan [--out <agents.json>]',
    '',
    'Find agents and MCP servers on this machine, by running process and known',
    'config paths. Reports what it could NOT check as gaps rather than omitting',
    'them.',
    '',
    '  --out <file>  write the findings as JSON',
  ],
  attach: [
    'orisan-rec attach <config> --log <dir>',
    '',
    'Route an MCP config through the recorder, backing up the original exactly.',
    '',
    '  --log <dir>   log directory the shim records into (required)',
  ],
  detach: [
    'orisan-rec detach <config> [--discard-backup]',
    '',
    'Restore the original config byte for byte from the backup attach made.',
    '',
    '  --discard-backup   remove the backup after restoring',
  ],
  demo: [
    'orisan-rec demo <dir> [--events N] [--with-ui]',
    '',
    'Write a fabricated session into <dir>. Labelled as fabricated: this is not',
    'a real agent and nothing here should be shown as product output.',
    '',
    '  --events N    how many events (default 40)',
    '  --with-ui     open the interface afterwards',
  ],
  ui: [
    'orisan-rec ui <dir> [--port N] [--payload-key <path>]',
    '',
    'Serve the local interface for a log. Loopback only, no authentication.',
    '',
    '  --port N              port (default ' + String(DEFAULT_PORT) + ')',
    '  --payload-key <path>  decrypt and display captured context',
    '  --key <path>          signing key',
    '  --witness <file>      witness receipts to check against',
    '  --tsa-ca <pem>        CA bundle for timestamp verification',
  ],
  tap: [
    'orisan-rec tap <dir> --upstream <url> [--port N]',
    '',
    'Record model calls through an HTTP tap. Fail-open: if capture fails the',
    'agent still works.',
    '',
    '  --upstream <url>      the provider to forward to (required)',
    '  --port N              listen port (default ' + String(DEFAULT_TAP_PORT) + ')',
    '  --payload-key <path>  encrypt captured context to this key',
    '  --key <path>          signing key',
    '  --no-context          record that a call happened, not what was in it',
  ],
  chain: [
    'orisan-rec chain <dir>',
    '',
    'Chain-integrity check ONLY. This is not verify: it cannot see a chain that',
    'was recomputed from genesis, nor events deleted from the end. It answers',
    '"are these records consistent with each other", which a careful attacker',
    'can satisfy.',
  ],
  checkpoint: [
    'orisan-rec checkpoint <dir> [--key <path>]',
    '',
    'Cut a signed checkpoint over every event not already covered by one.',
    '',
    '  --key <path>   signing key (default: the log\'s own)',
  ],
  anchor: [
    'orisan-rec anchor <dir> [--tsa <url>]',
    '',
    'Get an RFC 3161 timestamp over any unanchored checkpoint. Anchoring is',
    'fail-open: a failure queues rather than blocking recording.',
    '',
    '  --tsa <url>   timestamp authority (default ' + DEFAULT_TSA_URL + ')',
  ],
  witness: [
    'orisan-rec witness register <dir> --url <witness>',
    'orisan-rec witness submit <dir>',
    'orisan-rec witness repoint <dir> --url <new>',
    '',
    'An external witness is what makes completeness provable: it remembers what',
    'this log contained, so deleting the end of the log shows up as a',
    'disagreement rather than as a shorter log.',
    '',
    '  register   pin the witness public key and register this log',
    '  submit     send any checkpoints the witness has not seen',
    '  repoint    move a log to a new witness hostname, or refuse and say why',
  ],
  verify: [
    'orisan-rec verify <dir> [--witness <file>] [--tsa-ca <pem>] [--tsa <url>]',
    '',
    'Full verification. Exit codes are the contract:',
    '',
    '  0  clean          every check ran and passed',
    '  1  tampered       a check failed',
    '  2  cannot-verify  a check could not be completed — NEVER a pass',
    '',
    '  --witness <file>  witness receipts; without one, completeness cannot be',
    '                    established and the result is exit 2',
    '  --tsa-ca <pem>    CA bundle openssl checks the timestamp against',
    '  --tsa <url>       pin the expected timestamp authority',
  ],
};

/**
 * Which argv slot holds a path, per command.
 *
 * Commands absent from this map take no positional path. `witness` is at 2
 * because argv[1] is its subcommand.
 */
const POSITIONAL_AT: Record<string, number> = {
  attach: 1, detach: 1, demo: 1, ui: 1, tap: 1,
  chain: 1, checkpoint: 1, anchor: 1, verify: 1, witness: 2,
};

function helpFor(cmd: string): string | null {
  const lines = COMMAND_HELP[cmd];
  return lines ? `${lines.join('\n')}\n` : null;
}

function wantsHelp(argv: string[]): boolean {
  return argv.includes('--help') || argv.includes('-h');
}

/**
 * Refuse to treat a flag as a path.
 *
 * Returns an error message, or null if the positional is fine. Without this,
 * a mistyped flag becomes a directory name and the command reports success.
 */
function badPositional(cmd: string, argv: string[]): string | null {
  const idx = POSITIONAL_AT[cmd];
  if (idx === undefined) return null;
  const value = argv[idx];
  if (value === undefined || !value.startsWith('-')) return null;
  return `${cmd}: expected a directory, got the flag "${value}".\n\n${helpFor(cmd) ?? usage()}`;
}

async function main(argv: string[]): Promise<number> {
  const [cmd, dir] = argv;

  if (!cmd || cmd === '--help' || cmd === '-h') {
    process.stdout.write(usage());
    return 0;
  }

  // Help before anything else touches the filesystem. `demo --help` used to
  // create a directory called `--help` and write 40 events into it.
  if (wantsHelp(argv)) {
    const text = helpFor(cmd);
    if (text) { process.stdout.write(text); return 0; }
    process.stdout.write(usage());
    return 0;
  }

  const bad = badPositional(cmd, argv);
  if (bad) { process.stderr.write(bad); return 2; }
  if (cmd === 'showcase') {
    const pauseFlag = flag(argv, '--pause');
    // Drive the real CLI as a subprocess: what is on screen is what ran.
    //
    // Resolved from THIS module, not via shimRunner, which prefers dist/. In a
    // checkout dist can be older than src, and the first run of this command
    // silently demoed a stale build that lacked a fix made minutes earlier.
    // The showcase has to run the code you invoked, or it is demonstrating
    // something other than what you are looking at.
    const here = fileURLToPath(import.meta.url);
    const self = here.endsWith('.ts')
      ? [pathJoin(here, '..', '..', 'node_modules', '.bin', 'tsx'), here]
      : [process.execPath, here];

    const r = await runShowcase({
      cli: self,
      ...(pauseFlag !== undefined ? { pauseMs: Number.parseInt(pauseFlag, 10) } : {}),
      ...(argv.includes('--keep') ? { keep: true } : {}),
      ...(flag(argv, '--dir') !== undefined ? { dir: flag(argv, '--dir')! } : {}),
      ...(flag(argv, '--witness') !== undefined ? { witnessUrl: flag(argv, '--witness')! } : {}),
      ...(flag(argv, '--tsa') !== undefined ? { tsaUrl: flag(argv, '--tsa')! } : {}),
      ...(flag(argv, '--tsa-ca') !== undefined ? { tsaCaFile: flag(argv, '--tsa-ca')! } : {}),
      ...(argv.includes('--plain') ? { plain: true } : {}),
    });
    // A demo that fails must exit non-zero, or CI would call it a pass.
    return r.ok ? 0 : 1;
  }

  if (cmd === 'start') {
    const r = prepareStart({ ...(argv.includes('--no-demo') ? { noDemo: true } : {}) });
    const portFlag = flag(argv, '--port');
    const runner = shimRunner();
    const { port } = await startServer({
      logDir: r.home.logDir,
      port: portFlag !== undefined ? Number.parseInt(portFlag, 10) : DEFAULT_PORT,
      shimPath: runner.shimPath,
      nodePath: runner.nodePath,
      signingKeyPath: r.home.signingKey,
      payloadKeyPath: r.home.payloadKey,
      orisanHome: r.home.root,
    });
    const url = `http://127.0.0.1:${port}`;
    process.stdout.write(startBanner(r, url));
    try {
      const opener = process.platform === 'darwin' ? 'open' : 'xdg-open';
      spawn(opener, [url], { stdio: 'ignore', detached: true }).unref();
    } catch { /* a browser that will not open is not a reason to exit */ }
    await new Promise(() => undefined);
    return 0;
  }

  if (cmd === 'scan') {
    const result = scan();
    const out = flag(argv, '--out');
    if (out !== undefined) {
      writeFileSync(out, `${JSON.stringify(result, null, 2)}\n`);
    }

    const total = serverCount(result);
    process.stdout.write(`scanned ${result.home} (${result.platform})\n\n`);
    if (result.surfaces.length === 0) {
      process.stdout.write('  no agents or MCP servers found\n');
    }
    for (const s of result.surfaces) {
      process.stdout.write(`  ${s.surface}${s.config_path ? `  ${s.config_path}` : ''}\n`);
      if (s.servers.length === 0) process.stdout.write('    (configured, no servers)\n');
      for (const srv of s.servers) {
        const where = srv.source === 'process' ? `pid ${srv.pid}` : 'config';
        process.stdout.write(`    ${srv.name.padEnd(24)} ${srv.command} ${srv.args.join(' ')}`.trimEnd() + `  [${where}]\n`);
      }
    }
    process.stdout.write(`\n  ${total} server(s) across ${result.surfaces.length} surface(s)\n`);
    for (const g of result.gaps) process.stdout.write(`  GAP: ${g}\n`);
    if (out !== undefined) process.stdout.write(`\n  wrote ${out}\n`);
    // Discovery finding nothing is a legitimate answer, not an error.
    return 0;
  }

  if (cmd === 'attach') {
    const config = argv[1];
    const log = flag(argv, '--log');
    if (!config || !log) {
      process.stderr.write('attach requires <config> and --log <dir>\n');
      return 2;
    }
    try {
      const runner = shimRunner();
      const r = attach(config, {
        logDir: log,
        shimPath: runner.shimPath,
        nodePath: runner.nodePath,
        ...(flag(argv, '--key') !== undefined ? { signingKeyPath: flag(argv, '--key')! } : {}),
        ...(flag(argv, '--witness') !== undefined ? { witnessFile: flag(argv, '--witness')! } : {}),
      });
      process.stdout.write(
        `attached ${r.configPath}\n` +
        `  backup   ${r.backupPath}\n` +
        `  recording ${r.rewritten.length ? r.rewritten.join(', ') : '(none)'}\n` +
        (r.skipped.length ? `  skipped  ${r.skipped.join(', ')} (no stdio command)\n` : '') +
        '  restart the client for this to take effect\n',
      );
      return 0;
    } catch (e) {
      process.stderr.write(`attach failed: ${(e as Error).message}\n`);
      return 2;
    }
  }

  if (cmd === 'detach') {
    const config = argv[1];
    if (!config) { process.stderr.write('detach requires <config>\n'); return 2; }
    try {
      const r = detach(config);
      if (flag(argv, '--keep-backup') === undefined) discardBackup(config);
      process.stdout.write(
        `detached ${r.configPath}\n  restored byte-identical from ${r.restoredFrom}\n`,
      );
      return 0;
    } catch (e) {
      process.stderr.write(`detach failed: ${(e as Error).message}\n`);
      return 2;
    }
  }

  if (cmd === 'witness') {
    const sub = argv[1];
    const wdir = argv[2];
    if (!sub || !wdir) { process.stderr.write('usage: orisan-rec witness <register|submit> <dir> [--url <witness>]\n'); return 2; }

    if (sub === 'register') {
      const url = flag(argv, '--url');
      if (!url) { process.stderr.write('witness register requires --url\n'); return 2; }
      const keyPath = flag(argv, '--key');
      try {
        // Registering is a reasonable FIRST action on a new log — you set the
        // witness up before you record anything. The signing key does not
        // exist yet at that point, so create it rather than failing with
        // "signing key not found", which reads like a broken install.
        const key = existsSync(signingKeyPath(wdir, keyPath))
          ? loadSigningKey(wdir, keyPath)
          : generateSigningKey(wdir, keyPath);
        const cfg = await registerLog(wdir, key, { url });
        process.stdout.write(
          `registered with ${cfg.url}\n` +
          `  log_id        ${cfg.log_id}\n` +
          `  witness key   PINNED (${cfg.witness_pubkey_pem.split('\n')[1]?.slice(0, 24) ?? ''}…)\n` +
          '  this key is never re-learned; a response signed by any other key is treated as an attack\n',
        );
        return 0;
      } catch (e) {
        process.stderr.write(`witness register failed: ${(e as Error).message}\n`);
        return 2;
      }
    }

    if (sub === 'submit') {
      const cfg = readWitnessConfig(wdir);
      if (!cfg) { process.stderr.write('no witness configured; run `orisan-rec witness register` first\n'); return 2; }
      const key = loadSigningKey(wdir, flag(argv, '--key'));
      const pending = pendingSubmissions(wdir, readCheckpoints(wdir));
      if (pending.length === 0) { process.stdout.write('nothing pending: every checkpoint has a receipt\n'); return 0; }

      let failed = 0;
      let throttled = 0;
      for (const cp of pending) {
        try {
          // This command exists to drain the queue and is in nobody's hot
          // path, so it waits out throttling far longer than the recorder does.
          const r = await submitCheckpoint(wdir, cfg, key, cp, undefined, DRAIN_RETRY);
          if (r.ok) process.stdout.write(`  index ${r.index}  witnessed\n`);
          else if (r.throttled) {
            // Not a failure of this log: the witness asked us to come back.
            throttled++;
            process.stdout.write(`  index ${cp.index}  throttled, still queued: ${r.error}\n`);
          } else { failed++; process.stderr.write(`  index ${cp.index}  NOT witnessed: ${r.error}\n`); }
        } catch (e) {
          if (e instanceof WitnessKeyMismatch) {
            process.stderr.write(`\nATTACK: ${e.message}\n`);
            return 1;
          }
          throw e;
        }
      }
      if (throttled > 0) {
        process.stdout.write(
          `\n${throttled} checkpoint(s) were throttled, not refused. They stay queued; run this again shortly.\n`,
        );
      }
      // Throttling alone is not a cannot-verify: nothing was lost and nothing
      // is wrong with the log. Only a real refusal earns exit 2.
      return failed > 0 ? 2 : 0;
    }

    if (sub === 'repoint') {
      const url = flag(argv, '--url');
      if (!url) { process.stderr.write('witness repoint requires --url <new witness url>\n'); return 2; }
      const before = readWitnessConfig(wdir);
      const r = await repointWitness(wdir, url, readCheckpoints(wdir));
      if (!r.ok) {
        process.stderr.write(
          `refused to repoint (${r.refusal.code})\n\n  ${r.refusal.message}\n\n` +
          `  Still pointed at ${before?.url ?? '(not registered)'}. Nothing was changed.\n`,
        );
        return 1;
      }
      process.stdout.write(
        `repointed ${r.from}\n        -> ${r.to}\n` +
        `  log_id       ${r.config.log_id}\n` +
        `  pinned key   unchanged — the new address answered with the same key\n` +
        `  witness head index ${r.head.latest_index}, matching this log\n`,
      );
      return 0;
    }

    process.stderr.write(`unknown witness subcommand: ${sub}\n`);
    return 2;
  }

  if (!dir) {
    process.stderr.write(`${cmd} requires a directory\n`);
    return 2;
  }

  switch (cmd) {
    case 'demo': {
      const eventsFlag = flag(argv, '--events');
      const r = generateDemoSession(dir, {
        ...(eventsFlag !== undefined ? { count: Number.parseInt(eventsFlag, 10) } : {}),
      });
      process.stdout.write(
        `wrote ${r.events} events (${r.flagged} flagged) to ${r.dir}\n` +
        `head: seq=${r.head.seq} hash=${r.head.hash}\n`,
      );
      if (flag(argv, '--with-ui') !== undefined || argv.includes('--with-ui')) {
        // Cut a checkpoint so the UI has something beyond raw events. It stays
        // unanchored, so the banner shows the honest grey state rather than a
        // reassuring one — which is the point of demoing it at all.
        const rec = Recorder.open(dir, { anchor: { enabled: false } });
        await rec.cutCheckpoint('manual');
        rec.close();
        return await serveUi(dir, argv);
      }
      process.stdout.write('no checkpoints were cut; run `orisan-rec checkpoint` then `anchor`\n');
      return 0;
    }

    case 'ui':
      return await serveUi(dir, argv);

    case 'tap': {
      const upstream = flag(argv, '--upstream');
      if (!upstream) { process.stderr.write('tap requires --upstream <url>\n'); return 2; }
      const noContext = argv.includes('--no-context');
      const payloadKeyPath = flag(argv, '--payload-key');

      // Context capture requires a key. Refusing at startup is safe — no
      // workflow is running yet — whereas discovering it mid-session would
      // mean either dropping prompts silently or writing them in the clear.
      let payloadKey = null;
      if (!noContext) {
        if (!payloadKeyPath) {
          process.stderr.write(
            'tap requires --payload-key <path> so captured prompts can be encrypted.\n' +
            'Model calls carry the full context; there is no unencrypted path.\n' +
            'Use --no-context to record metadata only.\n',
          );
          return 2;
        }
        payloadKey = existsSync(payloadKeyPath) ? loadKeyFile(payloadKeyPath) : generateKeyFile(payloadKeyPath);
      }

      const recorder = Recorder.open(dir, {
        ...(flag(argv, '--key') !== undefined ? { signingKeyPath: flag(argv, '--key')! } : {}),
        anchor: { enabled: false },
      });
      const portFlag = flag(argv, '--port');
      const handle = await startTap({
        upstream,
        port: portFlag !== undefined ? Number.parseInt(portFlag, 10) : DEFAULT_TAP_PORT,
        recorder,
        payloadKey,
        logDir: dir,
      });

      process.stdout.write(
        `tap on http://127.0.0.1:${handle.port} -> ${upstream}\n` +
        `  session ${recorder.sessionId}\n` +
        (payloadKey
          ? `  context: captured and encrypted (key ${payloadKeyPath})\n`
          : '  context: NOT captured (--no-context); metadata only\n') +
        '  point your agent at this base URL, e.g.\n' +
        `    export ANTHROPIC_BASE_URL=http://127.0.0.1:${handle.port}\n` +
        '  recording never blocks a request: if capture fails, the call still goes through\n',
      );
      await new Promise(() => undefined);
      return 0;
    }

    case 'chain': {
      const { store, recovery } = EventStore.open(dir);
      if (recovery.truncatedPartialTail) {
        process.stdout.write(
          `recovered: discarded ${recovery.bytesDiscarded} byte partial tail from ${recovery.segment}\n`,
        );
      }
      const breaks = store.verifyChainOnly();
      const index = EventIndex.open(dir);
      const indexed = index.count();
      index.close();

      if (breaks.length === 0) {
        process.stdout.write(
          `chain intact: ${store.count} events, head ${store.head.hash}\n` +
          `index: ${indexed} rows\n` +
          'NOTE: this is chain integrity only. It cannot detect a chain recomputed\n' +
          '      from genesis. Use `orisan-rec verify` for that.\n',
        );
        return 0;
      }
      for (const b of breaks) {
        process.stderr.write(
          `BREAK seq=${b.seq} event_id=${b.event_id} reason=${b.reason}\n` +
          `  expected ${b.expected}\n  actual   ${b.actual}\n`,
        );
      }
      process.stderr.write(`chain broken: ${breaks.length} break(s)\n`);
      return 1;
    }

    case 'checkpoint': {
      const keyPath = flag(argv, '--key');
      const rec = Recorder.open(dir, {
        anchor: { enabled: false },
        ...(keyPath !== undefined ? { signingKeyPath: keyPath } : {}),
      });
      const cp = await rec.cutCheckpoint('manual');
      rec.close();
      if (!cp) {
        process.stdout.write('nothing to checkpoint: every event is already covered\n');
        return 0;
      }
      process.stdout.write(
        `checkpoint ${cp.seq_from}..${cp.seq_to} (${cp.count} events)\n` +
        `  merkle_root ${cp.merkle_root}\n` +
        '  unanchored — run `orisan-rec anchor` to commit it externally\n',
      );
      return 0;
    }

    case 'anchor': {
      const tsaUrl = flag(argv, '--tsa') ?? DEFAULT_TSA_URL;
      const cps = readCheckpoints(dir);
      const pending = pendingAnchors(dir, cps);
      if (pending.length === 0) {
        process.stdout.write(`nothing pending: ${cps.length} checkpoint(s), all anchored\n`);
        return 0;
      }
      process.stdout.write(`anchoring ${pending.length} checkpoint(s) to ${tsaUrl}\n`);
      const results = await drainAnchorQueue(dir, cps, { tsaUrl });
      let failed = 0;
      for (const r of results) {
        if (r.ok) {
          process.stdout.write(`  ..${r.seq_to}  anchored\n`);
        } else {
          failed++;
          process.stderr.write(`  ..${r.seq_to}  NOT anchored: ${r.error}\n`);
        }
      }
      if (failed > 0) {
        process.stderr.write(
          `${failed} checkpoint(s) still queued. Recording is unaffected; verify will\n` +
          'report cannot-verify for them until they are anchored.\n',
        );
        return 2;
      }
      return 0;
    }

    case 'verify': {
      // A configured witness service is consulted automatically. Its absence is
      // itself a finding, so there is no flag to forget.
      const wcfg = readWitnessConfig(dir);
      let witnessService;
      if (wcfg) {
        const fetched = await fetchHead(wcfg);
        witnessService = {
          logId: wcfg.log_id, url: wcfg.url,
          reachable: fetched.reachable,
          ...(fetched.error !== undefined ? { error: fetched.error } : {}),
          ...(fetched.head !== undefined ? { head: fetched.head } : {}),
          ...(fetched.signatureValid !== undefined ? { signatureValid: fetched.signatureValid } : {}),
        };
      }
      const report = verify(dir, {
        ...(witnessService !== undefined ? { witnessService } : {}),
        ...(flag(argv, '--tsa-ca') !== undefined ? { tsaCaFile: flag(argv, '--tsa-ca')! } : {}),
        ...(flag(argv, '--witness') !== undefined ? { witnessFile: flag(argv, '--witness')! } : {}),
        ...(flag(argv, '--tsa') !== undefined ? { expectedTsaUrl: flag(argv, '--tsa')! } : {}),
      });
      const out = formatReport(report, dir);
      if (report.verdict === 'clean') process.stdout.write(out);
      else process.stderr.write(out);
      return report.exitCode;
    }

    default:
      process.stderr.write(`unknown command: ${cmd}\n\n${usage()}`);
      return 2;
  }
}

main(process.argv.slice(2)).then((code) => {
  process.exitCode = code;
});

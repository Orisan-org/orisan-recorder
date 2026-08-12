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
import {
  fetchHead, pendingSubmissions, readWitnessConfig, registerLog, submitCheckpoint,
  WitnessKeyMismatch,
} from './witness-service.js';
import { loadSigningKey } from './checkpoint.js';

function usage(): string {
  return [
    'orisan-rec — recorder for AI agent actions',
    '',
    'Usage:',
    '  orisan-rec scan [--out <agents.json>]     find agents and MCP servers on this machine',
    '  orisan-rec attach <config> --log <dir>    route a config through the recorder',
    '  orisan-rec detach <config>                restore the original config exactly',
    '  orisan-rec demo <dir> [--with-ui]         write a fabricated session, optionally open the UI',
    '  orisan-rec ui <dir> [--port N]            serve the local UI on 127.0.0.1',
    '  orisan-rec chain <dir>                    chain-integrity check only (NOT verify)',
    '  orisan-rec checkpoint <dir> [--key <p>]   cut a checkpoint over uncovered events',
    '  orisan-rec anchor <dir> [--tsa <url>]     anchor any unanchored checkpoints',
    '  orisan-rec witness register <dir> --url <witness>   register and PIN the witness key',
    '  orisan-rec witness submit <dir>           submit any unwitnessed checkpoints',
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

async function main(argv: string[]): Promise<number> {
  const [cmd, dir] = argv;

  if (!cmd || cmd === '--help' || cmd === '-h') {
    process.stdout.write(usage());
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
        const key = loadSigningKey(wdir, keyPath);
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
      for (const cp of pending) {
        try {
          const r = await submitCheckpoint(wdir, cfg, key, cp);
          if (r.ok) process.stdout.write(`  index ${r.index}  witnessed\n`);
          else { failed++; process.stderr.write(`  index ${cp.index}  NOT witnessed: ${r.error}\n`); }
        } catch (e) {
          if (e instanceof WitnessKeyMismatch) {
            process.stderr.write(`\nATTACK: ${e.message}\n`);
            return 1;
          }
          throw e;
        }
      }
      return failed > 0 ? 2 : 0;
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
      const r = generateDemoSession(dir);
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

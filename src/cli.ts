#!/usr/bin/env node
/**
 * orisan-rec CLI.
 *
 * Exit codes for `verify` are the contract: 0 clean, 1 tampered,
 * 2 cannot-verify. Nothing may report 0 unless every check ran and passed.
 */

import { generateDemoSession } from './demo.js';
import { scan, serverCount } from './discover.js';
import { writeFileSync } from 'node:fs';
import { EventIndex } from './index-db.js';
import { EventStore } from './store.js';
import { Recorder } from './recorder.js';
import { readCheckpoints } from './checkpoint.js';
import { DEFAULT_TSA_URL, drainAnchorQueue, pendingAnchors } from './tsa.js';
import { formatReport, verify } from './verify.js';

function usage(): string {
  return [
    'orisan-rec — recorder for AI agent actions',
    '',
    'Usage:',
    '  orisan-rec scan [--out <agents.json>]     find agents and MCP servers on this machine',
    '  orisan-rec demo <dir>                     write a fabricated 40-event session',
    '  orisan-rec chain <dir>                    chain-integrity check only (NOT verify)',
    '  orisan-rec checkpoint <dir> [--key <p>]   cut a checkpoint over uncovered events',
    '  orisan-rec anchor <dir> [--tsa <url>]     anchor any unanchored checkpoints',
    '  orisan-rec verify <dir> [--tsa-ca <pem>] [--witness <file>] [--tsa <url>]',
    '                                            full verification',
    '',
    'verify exit codes:  0 clean   1 tampered   2 cannot-verify',
    'A cannot-verify result is never a pass.',
    '',
  ].join('\n');
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

  if (!dir) {
    process.stderr.write(`${cmd} requires a directory\n`);
    return 2;
  }

  switch (cmd) {
    case 'demo': {
      const r = generateDemoSession(dir);
      process.stdout.write(
        `wrote ${r.events} events (${r.flagged} flagged) to ${r.dir}\n` +
        `head: seq=${r.head.seq} hash=${r.head.hash}\n` +
        'no checkpoints were cut; run `orisan-rec checkpoint` then `anchor`\n',
      );
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
      const report = verify(dir, {
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

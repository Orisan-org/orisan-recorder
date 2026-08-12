#!/usr/bin/env node
/**
 * Minimal CLI. Only the subcommands whose slices are built are wired up.
 *
 * `verify` is deliberately NOT implemented here: it is R1.4, it depends on the
 * signed checkpoints and RFC 3161 anchors of R1.3, and a stub that printed
 * anything reassuring would be worse than its absence. It exits 2
 * (cannot-verify) if invoked, which is the exit code the spec reserves for
 * "no verdict" — never mistaken for success.
 */

import { generateDemoSession } from './demo.js';
import { EventIndex } from './index-db.js';
import { EventStore } from './store.js';

function usage(): string {
  return [
    'orisan-rec — recorder for AI agent actions',
    '',
    'Usage:',
    '  orisan-rec demo <dir>       write a fabricated 40-event session',
    '  orisan-rec chain <dir>      chain-integrity check only (NOT verify)',
    '  orisan-rec verify <dir>     not implemented until R1.3/R1.4 land',
    '',
  ].join('\n');
}

function main(argv: string[]): number {
  const [cmd, dir] = argv;

  if (!cmd || cmd === '--help' || cmd === '-h') {
    process.stdout.write(usage());
    return 0;
  }

  if (cmd === 'demo') {
    if (!dir) { process.stderr.write('demo requires a directory\n'); return 2; }
    const r = generateDemoSession(dir);
    process.stdout.write(
      `wrote ${r.events} events (${r.flagged} flagged) to ${r.dir}\nhead: seq=${r.head.seq} hash=${r.head.hash}\n`,
    );
    return 0;
  }

  if (cmd === 'chain') {
    if (!dir) { process.stderr.write('chain requires a directory\n'); return 2; }
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
        '      from genesis. That requires the anchored checkpoints of R1.3/R1.4.\n',
      );
      return 0;
    }
    for (const b of breaks) {
      process.stderr.write(`BREAK seq=${b.seq} event_id=${b.event_id} reason=${b.reason}\n` +
        `  expected ${b.expected}\n  actual   ${b.actual}\n`);
    }
    process.stderr.write(`chain broken: ${breaks.length} break(s)\n`);
    return 1;
  }

  if (cmd === 'verify') {
    process.stderr.write(
      'verify is not implemented yet (R1.4).\n' +
      'It requires the signed, RFC 3161-anchored checkpoints of R1.3.\n' +
      'Use `orisan-rec chain <dir>` for chain integrity only — that check\n' +
      'cannot detect a recomputed chain and must never be reported as a pass.\n',
    );
    return 2;
  }

  process.stderr.write(`unknown command: ${cmd}\n\n${usage()}`);
  return 2;
}

process.exitCode = main(process.argv.slice(2));

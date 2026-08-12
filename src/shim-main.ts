#!/usr/bin/env node
/**
 * Entry point the rewritten config points at:
 *   node shim-main.js --log <dir> --name <server> [--key p] [--witness w] -- <cmd> <args...>
 */
import { runShim } from './shim.js';

function main(): void {
  const argv = process.argv.slice(2);
  const sep = argv.indexOf('--');
  if (sep === -1) {
    process.stderr.write('orisan shim: expected "--" before the wrapped command\n');
    process.exit(2);
  }
  const flags = argv.slice(0, sep);
  const rest = argv.slice(sep + 1);
  const get = (n: string): string | undefined => {
    const i = flags.indexOf(n);
    return i >= 0 ? flags[i + 1] : undefined;
  };

  const logDir = get('--log');
  const name = get('--name');
  const command = rest[0];
  if (!logDir || !name || !command) {
    process.stderr.write('orisan shim: --log, --name and a command are required\n');
    process.exit(2);
  }

  void runShim({
    logDir,
    serverName: name,
    command,
    args: rest.slice(1),
    ...(get('--key') !== undefined ? { signingKeyPath: get('--key')! } : {}),
    ...(get('--witness') !== undefined ? { witnessFile: get('--witness')! } : {}),
  }).then((code) => { process.exitCode = code; });
}

main();

/**
 * R5 — `orisan-rec start`: the one command.
 *
 * Design rule, from the spec and worth restating because it is easy to lose:
 * THE FIRST RUN MUST WORK WITH NOTHING SET UP. No witness, no payload key, no
 * timestamp authority certificate, no config file. It records, it shows you
 * something, and then it tells you plainly what each missing piece would buy.
 *
 * A tool that demands three secrets before its first screen gets deleted before
 * anyone learns what it does. A tool that quietly pretends those secrets are
 * optional is worse. So: everything that can be created locally is created
 * locally, everything that genuinely requires a decision is named, and the
 * banner never claims more than what is actually set up.
 *
 * Key custody matters even here: keys go in ~/.orisan/keys, never in the log
 * directory, because verify reports a key stored beside the data it signs.
 */

import { existsSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

import { generateSigningKey, loadSigningKey, readCheckpoints } from './checkpoint.js';
import { generateDemoSession } from './demo.js';
import { generateKeyFile, loadKeyFile } from './payloads.js';
import { Recorder } from './recorder.js';
import { EventStore } from './store.js';
import { DEFAULT_WITNESS_URL, readWitnessConfig } from './witness-service.js';

/**
 * How to invoke this CLI, as the reader would have to type it.
 *
 * Printing `orisan-rec …` to someone running from a checkout hands them a
 * command that does not exist: the name is only on PATH after a global install,
 * and today the checkout is the only install route that works. So the commands
 * we offer are built from how THIS process was actually started, and a copied
 * line runs as-is.
 */
export function cliInvocation(argv1: string | undefined = process.argv[1]): string {
  if (!argv1) return 'orisan-rec';
  // A global or linked install runs through a shim named for the command; a
  // checkout runs the built entry point directly.
  return /(^|[/\\])dist[/\\]cli\.js$/.test(argv1) ? `node ${resolve(argv1)}` : 'orisan-rec';
}

export interface OrisanHome {
  root: string;
  logDir: string;
  keysDir: string;
  signingKey: string;
  payloadKey: string;
}

export function defaultHome(root = join(homedir(), '.orisan')): OrisanHome {
  return {
    root,
    logDir: join(root, 'logs', 'default'),
    keysDir: join(root, 'keys'),
    signingKey: join(root, 'keys', 'signing.key'),
    payloadKey: join(root, 'keys', 'payload.key'),
  };
}

export interface SetupStep {
  /** Short imperative label. */
  label: string;
  /** Why it matters, in plain English. */
  why: string;
  /** The command to run, if there is one. */
  command?: string;
  done: boolean;
}

/**
 * What is set up, and what each missing piece would buy.
 *
 * Shown in the terminal after `start` and served to the UI, so the answer to
 * "why isn't this green?" is in the same words in both places.
 */
export function setupSteps(home: OrisanHome): SetupStep[] {
  const cli = cliInvocation();
  const witness = existsSync(home.logDir) ? readWitnessConfig(home.logDir) : null;
  const hasCheckpoint = existsSync(home.logDir) && readCheckpoints(home.logDir).length > 0;
  const anchored = existsSync(join(home.logDir, 'anchors'));

  return [
    {
      label: 'Record something',
      why: 'Nothing is recorded until you switch it on for an agent, or run the demo.',
      command: `${cli} scan`,
      done: existsSync(home.logDir) && EventStore.open(home.logDir, { readOnly: true }).store.count > 0,
    },
    {
      label: 'Summarise what has been recorded',
      why: 'Batches are signed as they are made, so a later edit stops matching.',
      command: `${cli} checkpoint ${home.logDir}`,
      done: hasCheckpoint,
    },
    {
      label: 'Get an outside timestamp',
      why: 'Proves a batch already existed by a certain time, checkable by anyone with openssl.',
      command: `${cli} anchor ${home.logDir}`,
      done: anchored,
    },
    {
      label: 'Register a witness — this is what green needs',
      why:
        'Without one, nothing can tell whether records were deleted from the end of the log, because what is '
        + 'left still looks consistent. A witness keeps its own note outside this machine, so deletions here '
        + 'show up as a disagreement. Until then the banner stays grey, which is honest rather than reassuring. '
        + `With no --url this registers with ${DEFAULT_WITNESS_URL}, which Orisan runs: it defends against `
        + 'tampering by whoever holds this machine, not against Orisan. Pass --url to use a witness we do not '
        + 'run; the witness key is pinned at registration either way.',
      command: `${cli} witness register ${home.logDir}`,
      done: witness !== null,
    },
  ];
}

export interface StartResult {
  home: OrisanHome;
  seeded: boolean;
  events: number;
  steps: SetupStep[];
}

export interface StartOptions {
  home?: OrisanHome;
  /** Skip seeding a demo into an empty log. */
  noDemo?: boolean;
}

/**
 * Prepare everything a first run needs. Does not start the server; the CLI
 * does that, so this stays testable without a socket.
 */
export function prepareStart(opts: StartOptions = {}): StartResult {
  const home = opts.home ?? defaultHome();
  mkdirSync(home.logDir, { recursive: true });
  mkdirSync(home.keysDir, { recursive: true });

  // Keys are created for you. They are local files on your own machine, and
  // making you generate them by hand before the first screen buys nothing.
  if (!existsSync(home.signingKey)) generateSigningKey(home.logDir, home.signingKey);
  else loadSigningKey(home.logDir, home.signingKey);
  if (!existsSync(home.payloadKey)) generateKeyFile(home.payloadKey);
  else loadKeyFile(home.payloadKey);

  let seeded = false;
  const existing = EventStore.open(home.logDir, { readOnly: true }).store.count;
  if (existing === 0 && !opts.noDemo) {
    // An empty first screen teaches nothing. A fabricated session is clearly
    // labelled as such in the UI and gives the tour something to point at.
    generateDemoSession(home.logDir, { sessions: 3 });
    seeded = true;
  }

  const events = EventStore.open(home.logDir, { readOnly: true }).store.count;

  // A checkpoint so the timeline has a signed batch to talk about. Anchoring
  // needs the network, so it is left as a suggested step rather than done here.
  if (events > 0 && readCheckpoints(home.logDir).length === 0) {
    const rec = Recorder.open(home.logDir, {
      signingKeyPath: home.signingKey, anchor: { enabled: false }, submitToWitness: false,
    });
    void rec.cutCheckpoint('manual');
    rec.close();
  }

  return { home, seeded, events, steps: setupSteps(home) };
}

/** The terminal message after `start`. Kept here so a test can read it. */
export function startBanner(r: StartResult, url: string): string {
  const lines: string[] = [];
  lines.push('');
  lines.push(`  Orisan Recorder is running at ${url}`);
  lines.push('');
  if (r.seeded) {
    lines.push('  This is a fresh install, so a short example session has been written in');
    lines.push('  so there is something to look at. It is clearly fabricated, and you can');
    lines.push('  delete it any time:');
    lines.push(`      rm -rf ${r.home.logDir}`);
    lines.push('');
  }
  lines.push(`  Records   ${r.home.logDir}`);
  lines.push(`  Keys      ${r.home.keysDir}  (kept out of the log folder on purpose)`);
  lines.push('');
  lines.push('  Where you are:');
  for (const s of r.steps) {
    lines.push(`    [${s.done ? 'x' : ' '}] ${s.label}`);
  }
  const next = r.steps.find((s) => !s.done);
  if (next) {
    lines.push('');
    lines.push(`  Next: ${next.label}`);
    lines.push(`    ${next.why}`);
    if (next.command) lines.push(`    ${next.command}`);
  }
  lines.push('');
  lines.push('  The banner in the interface will stay grey until a witness is registered.');
  lines.push('  That is not a warning — it means completeness has not been established yet,');
  lines.push('  and the interface says so rather than implying more than it can show.');
  lines.push('');
  return lines.join('\n');
}

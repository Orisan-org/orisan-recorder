/**
 * A real witness service, in-process, for the W1 attack tests.
 *
 * Not a mock: the actual WitnessDb, WitnessService and HTTP server from the
 * orisan-witness sibling repository, over a loopback socket. A mocked witness
 * would agree with whatever the client expects, which is precisely the thing
 * these tests must not assume.
 *
 * THE SIBLING IS OPTIONAL. It is a separate, unpublished repository, so a
 * public clone of this one does not have it. Rather than four suites failing
 * to load — which is what happened, and which made `npm test` on a fresh clone
 * show four red files — the suites that need it SKIP, visibly, and run
 * untouched when it is present.
 *
 * A skip is never a pass. Vitest reports skipped tests in its own right, each
 * suite title says what is missing, and test/setup.ts prints a banner naming
 * the checks that did not run. Silence here would be the same defect the
 * scanner's own gap reporting exists to prevent: "nothing found" and "we did
 * not look" must not render the same.
 */
import { existsSync } from 'node:fs';
import { mkdtempSync, rmSync } from 'node:fs';
import { networkInterfaces, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

/**
 * Where the witness service's sources are.
 *
 * Defaults to a sibling checkout, which is the layout a developer with both
 * repositories has. ORISAN_WITNESS_SRC overrides it, because CI checks the
 * witness out inside its own workspace — a runner cannot place a repository
 * beside the workspace — and because nobody should have to arrange their
 * directories a particular way to run a test suite.
 */
export const WITNESS_SRC =
  process.env['ORISAN_WITNESS_SRC'] ?? join(here, '..', '..', '..', 'orisan-witness', 'src');

/** Is the real witness service available to run against? */
export const witnessAvailable: boolean = existsSync(join(WITNESS_SRC, 'db.ts'));

export const WITNESS_SKIP_REASON =
  'needs the orisan-witness service: a sibling checkout at ../orisan-witness, ' +
  'or ORISAN_WITNESS_SRC pointing at its src directory';

export interface LiveWitness {
  url: string;
  pubkeyPem: string;
  dir: string;
  stop: () => Promise<void>;
}

/**
 * A non-loopback address this machine answers on, or null.
 *
 * verify refuses to count a witness on 127.0.0.1: a witness the operator can
 * reach over loopback is one the operator controls, so agreement with it proves
 * only that the log agrees with itself. That rule is correct, and it means a
 * test that wants to see a GREEN verdict cannot use a loopback witness. Binding
 * the fixture to the machine's own LAN address gives a witness that is still
 * entirely local — no external network — but is not loopback.
 */
export function nonLoopbackAddress(): string | null {
  for (const addrs of Object.values(networkInterfaces())) {
    for (const a of addrs ?? []) {
      if (a.family === 'IPv4' && !a.internal && !/^127\./.test(a.address)) return a.address;
    }
  }
  return null;
}

export interface StartWitnessOptions {
  /**
   * Serve on all interfaces and advertise the LAN address, so verify does not
   * discount the witness as loopback. Only for tests that assert a clean
   * verdict; everything else should stay on 127.0.0.1.
   */
  reachable?: boolean;
}

export async function startWitness(opts: StartWitnessOptions = {}): Promise<LiveWitness> {
  if (!witnessAvailable) {
    // Reached only if a suite forgot to guard itself. Loud, not silent.
    throw new Error(
      `startWitness() called but the witness service is not present: ${WITNESS_SKIP_REASON}. ` +
        'Guard the suite with `witnessSuite` / `describe.skipIf(!witnessAvailable)`.',
    );
  }

  // Imported dynamically so this module loads without the sibling present: a
  // static import fails at collection and takes the whole file with it.
  //
  // The specifier is BUILT rather than written as a literal, so TypeScript
  // does not try to resolve it. tsc resolves the argument of `import()` when
  // it is a string literal, and would then fail `npm run typecheck` in exactly
  // the clone this change exists to make work. The module is genuinely
  // optional; only the runtime can know whether it is there.
  // By absolute file URL, not by package specifier. A bare specifier would
  // need a build alias, and a TEMPLATE specifier is invisible to that alias —
  // which is how the first version of this threw inside beforeAll while
  // `witnessAvailable` was correctly true. An absolute path needs no alias and
  // is still opaque to tsc, which is the property both ends need.
  const load = async (name: string): Promise<Record<string, unknown>> =>
    (await import(pathToFileURL(join(WITNESS_SRC, `${name}.ts`)).href)) as Record<string, unknown>;

  const [dbMod, keyMod, svcMod, srvMod] = await Promise.all([
    load('db'), load('keys'), load('service'), load('server'),
  ]);

  const WitnessDb = dbMod['WitnessDb'] as new (path: string) => { close(): void };
  const loadOrCreateKey = keyMod['loadOrCreateKey'] as (path: string) => unknown;
  const WitnessService = svcMod['WitnessService'] as new (
    db: unknown, key: unknown,
  ) => { publicKeyPem: string };
  const startServer = srvMod['startServer'] as (
    opts: unknown,
  ) => Promise<{ port: number; close: () => Promise<void> }>;

  const dir = mkdtempSync(join(tmpdir(), 'witness-svc-'));
  const db = new WitnessDb(join(dir, 'w.db'));
  const key = loadOrCreateKey(join(dir, 'k.pem'));
  const service = new WitnessService(db, key);
  const lan = opts.reachable === true ? nonLoopbackAddress() : null;
  const bindHost = lan !== null ? '0.0.0.0' : '127.0.0.1';
  const s = await startServer({ service, port: 0, host: bindHost, log: () => undefined });
  return {
    url: `http://${lan ?? '127.0.0.1'}:${s.port}`,
    pubkeyPem: service.publicKeyPem,
    dir,
    stop: async () => { await s.close(); db.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}

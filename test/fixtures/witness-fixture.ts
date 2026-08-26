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
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

/** Where the sibling checkout is expected, relative to this repository. */
export const WITNESS_SRC = join(here, '..', '..', '..', 'orisan-witness', 'src');

/** Is the real witness service available to run against? */
export const witnessAvailable: boolean = existsSync(join(WITNESS_SRC, 'db.ts'));

export const WITNESS_SKIP_REASON =
  'needs the orisan-witness sibling checkout at ../orisan-witness (a separate repository)';

export interface LiveWitness {
  url: string;
  pubkeyPem: string;
  dir: string;
  stop: () => Promise<void>;
}

export async function startWitness(): Promise<LiveWitness> {
  if (!witnessAvailable) {
    // Reached only if a suite forgot to guard itself. Loud, not silent.
    throw new Error(
      `startWitness() called but the witness service is not present: ${WITNESS_SKIP_REASON}. ` +
        'Guard the suite with `describe.skipIf(!witnessAvailable)`.',
    );
  }
  // Imported dynamically so this module loads without the sibling present.
  // A static import would fail at collection and take the whole file with it.
  const [{ WitnessDb }, { loadOrCreateKey }, { WitnessService }, { startServer }] = await Promise.all([
    import('orisan-witness/src/db.js'),
    import('orisan-witness/src/keys.js'),
    import('orisan-witness/src/service.js'),
    import('orisan-witness/src/server.js'),
  ]);

  const dir = mkdtempSync(join(tmpdir(), 'witness-svc-'));
  const db = new WitnessDb(join(dir, 'w.db'));
  const key = loadOrCreateKey(join(dir, 'k.pem'));
  const service = new WitnessService(db, key);
  const s = await startServer({ service, port: 0, host: '127.0.0.1', log: () => undefined });
  return {
    url: `http://127.0.0.1:${s.port}`,
    pubkeyPem: service.publicKeyPem,
    dir,
    stop: async () => { await s.close(); db.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}

/**
 * A real witness service, in-process, for the W1 attack tests.
 *
 * Not a mock: the actual WitnessDb, WitnessService and HTTP server from
 * ~/Orisan/orisan-witness, over a loopback socket. A mocked witness would
 * agree with whatever the client expects, which is precisely the thing these
 * tests must not assume.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { WitnessDb } from 'orisan-witness/src/db.js';
import { loadOrCreateKey } from 'orisan-witness/src/keys.js';
import { WitnessService } from 'orisan-witness/src/service.js';
import { startServer } from 'orisan-witness/src/server.js';

export interface LiveWitness {
  url: string;
  pubkeyPem: string;
  dir: string;
  db: WitnessDb;
  stop: () => Promise<void>;
}

export async function startWitness(): Promise<LiveWitness> {
  const dir = mkdtempSync(join(tmpdir(), 'witness-svc-'));
  const db = new WitnessDb(join(dir, 'w.db'));
  const key = loadOrCreateKey(join(dir, 'k.pem'));
  const service = new WitnessService(db, key);
  const s = await startServer({ service, port: 0, host: '127.0.0.1', log: () => undefined });
  return {
    url: `http://127.0.0.1:${s.port}`,
    pubkeyPem: service.publicKeyPem,
    dir,
    db,
    stop: async () => { await s.close(); db.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}

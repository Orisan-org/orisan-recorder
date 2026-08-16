/**
 * A local RFC 3161 Timestamp Authority for tests.
 *
 * The adversarial review found five ways to reach exit 0 on a tampered log, and
 * the reason none were caught is that no test ever reached a CLEAN verdict:
 * every one passed skipOpenssl or a bad CA, so exit 0 was only asserted as
 * unreachable and the whole success path went unexercised. This fixture exists
 * to make the success path testable offline, so every attack can be run against
 * a log that genuinely verifies clean.
 *
 * Real openssl, a real CA, a real timeStamping certificate, real tokens that
 * real `openssl ts -verify` accepts. No network.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { AnchorOptions } from '../../src/tsa.js';

export interface LocalTsa {
  /** CA bundle to pass as --tsa-ca. */
  caFile: string;
  /** The URL callers should record; the fixture answers regardless of value. */
  url: string;
  fetchImpl: NonNullable<AnchorOptions['fetchImpl']>;
  /** Anchor options ready to hand to Recorder/anchorCheckpoint. */
  anchorOptions: AnchorOptions;
  dir: string;
  /** Replies produced so far — lets a test assert the TSA was really called. */
  callCount(): number;
  cleanup(): void;
}

const OPENSSL = 'openssl';

function sh(args: string[], cwd: string): void {
  execFileSync(OPENSSL, args, { cwd, stdio: ['ignore', 'ignore', 'pipe'] });
}

/**
 * Stand up a throwaway TSA. Cheap enough per test file (~1s of RSA keygen);
 * call once in a beforeAll and share it.
 */
export function startLocalTsa(url = 'https://tsa.test.invalid/tsr'): LocalTsa {
  const dir = mkdtempSync(join(tmpdir(), 'orisan-tsa-fixture-'));
  let calls = 0;

  sh(['req', '-x509', '-newkey', 'rsa:2048', '-keyout', 'ca.key', '-out', 'ca.crt',
      '-days', '2', '-nodes', '-subj', '/CN=Orisan Test TSA CA'], dir);
  sh(['req', '-newkey', 'rsa:2048', '-keyout', 'tsa.key', '-out', 'tsa.csr',
      '-nodes', '-subj', '/CN=Orisan Test TSA'], dir);
  writeFileSync(join(dir, 'tsa.ext'), 'extendedKeyUsage=critical,timeStamping\n');
  sh(['x509', '-req', '-in', 'tsa.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
      '-CAcreateserial', '-out', 'tsa.crt', '-days', '2', '-extfile', 'tsa.ext'], dir);

  writeFileSync(join(dir, 'tsaserial'), '01\n');
  writeFileSync(join(dir, 'tsa.cnf'), [
    '[ tsa ]',
    'default_tsa = tsa_config1',
    '',
    '[ tsa_config1 ]',
    `serial                 = ${join(dir, 'tsaserial')}`,
    'crypto_device          = builtin',
    `signer_cert            = ${join(dir, 'tsa.crt')}`,
    `certs                  = ${join(dir, 'ca.crt')}`,
    `signer_key             = ${join(dir, 'tsa.key')}`,
    'signer_digest          = sha256',
    'default_policy         = 1.2.3.4.1',
    'other_policies         = 1.2.3.4.5, 1.2.3.4.6',
    'digests                = sha256, sha512',
    'accuracy               = secs:1',
    'clock_precision_digits = 0',
    'ordering               = yes',
    'tsa_name               = yes',
    'ess_cert_id_chain      = no',
    'ess_cert_id_alg        = sha256',
    '',
  ].join('\n'));

  const fetchImpl: NonNullable<AnchorOptions['fetchImpl']> = async (_url, init) => {
    calls++;
    const reqPath = join(dir, `req-${calls}.tsq`);
    const respPath = join(dir, `resp-${calls}.tsr`);
    writeFileSync(reqPath, init.body);
    sh(['ts', '-reply', '-config', join(dir, 'tsa.cnf'), '-queryfile', reqPath, '-out', respPath], dir);
    const body = readFileSync(respPath);
    return {
      ok: true,
      status: 200,
      arrayBuffer: async () =>
        body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer,
    };
  };

  return {
    caFile: join(dir, 'ca.crt'),
    url,
    fetchImpl,
    anchorOptions: { tsaUrl: url, fetchImpl },
    dir,
    callCount: () => calls,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/**
 * The same local authority, reachable over HTTP.
 *
 * The showcase spawns the real CLI, which talks RFC 3161 over the network, so
 * testing it offline needs a real socket rather than an injected fetch.
 */
export interface LocalTsaServer {
  url: string;
  caFile: string;
  close: () => Promise<void>;
}

export async function startLocalTsaHttp(tsa: LocalTsa): Promise<LocalTsaServer> {
  const { createServer } = await import('node:http');
  const { execFileSync } = await import('node:child_process');
  const { writeFileSync: write, readFileSync: read } = await import('node:fs');
  let n = 0;

  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      try {
        const i = ++n;
        const reqPath = join(tsa.dir, `http-req-${i}.tsq`);
        const respPath = join(tsa.dir, `http-resp-${i}.tsr`);
        write(reqPath, Buffer.concat(chunks));
        execFileSync('openssl', [
          'ts', '-reply', '-config', join(tsa.dir, 'tsa.cnf'),
          '-queryfile', reqPath, '-out', respPath,
        ], { cwd: tsa.dir, stdio: ['ignore', 'ignore', 'pipe'] });
        const body = read(respPath);
        res.writeHead(200, { 'content-type': 'application/timestamp-reply', 'content-length': body.length });
        res.end(body);
      } catch (e) {
        res.writeHead(500);
        res.end((e as Error).message);
      }
    });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
      resolve({
        url: `http://127.0.0.1:${port}/tsr`,
        caFile: tsa.caFile,
        close: () => new Promise<void>((d) => { server.close(() => d()); }),
      });
    });
  });
}

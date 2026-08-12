/** Sign an arbitrary canonical string with the log's Ed25519 signing key. */
import { createPrivateKey, sign as edSign } from 'node:crypto';
import type { SigningKeyFile } from './checkpoint.js';

export function sign(kf: SigningKeyFile, canonical: string): string {
  const key = createPrivateKey({ key: Buffer.from(kf.private_key, 'base64'), format: 'der', type: 'pkcs8' });
  return edSign(null, Buffer.from(canonical, 'utf8'), key).toString('base64');
}

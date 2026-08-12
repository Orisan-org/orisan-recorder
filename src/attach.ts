/**
 * R2.2 — attach / detach.
 *
 * attach rewrites an MCP config so every server runs through our shim. The
 * backup is written FIRST, before a single byte of the original is touched, so
 * an interruption mid-write leaves a recoverable state rather than a config
 * that no longer starts the user's tools.
 *
 * detach restores the backup byte-for-byte. Not "semantically equivalent JSON"
 * — byte-identical. Users have comments, key order and formatting they care
 * about, and a tool that reformats someone's config while claiming to restore
 * it has not restored it. There is a test asserting exact bytes.
 */

import { copyFileSync, existsSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';

export const BACKUP_SUFFIX = '.orisan-backup';

/** Marker so we can tell our own rewrites from the user's own config. */
export const SHIM_MARKER = '__orisan_shim';

export interface AttachOptions {
  /** Where recorded events go. */
  logDir: string;
  /** Absolute path to the shim entry point. */
  shimPath: string;
  /** Node binary used to run the shim. */
  nodePath?: string;
  signingKeyPath?: string;
  witnessFile?: string;
}

interface McpServerEntry {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  [k: string]: unknown;
}

export function backupPathFor(configPath: string): string {
  return `${configPath}${BACKUP_SUFFIX}`;
}

/** True if this config has already been rewritten by us. */
export function isAttached(configPath: string): boolean {
  if (!existsSync(configPath)) return false;
  return readFileSync(configPath, 'utf8').includes(SHIM_MARKER);
}

function serversBlock(doc: Record<string, unknown>): Record<string, McpServerEntry> | null {
  if (doc['mcpServers'] && typeof doc['mcpServers'] === 'object') {
    return doc['mcpServers'] as Record<string, McpServerEntry>;
  }
  const mcp = doc['mcp'];
  if (mcp && typeof mcp === 'object') {
    const inner = (mcp as Record<string, unknown>)['servers'];
    if (inner && typeof inner === 'object') return inner as Record<string, McpServerEntry>;
  }
  return null;
}

export interface AttachResult {
  configPath: string;
  backupPath: string;
  rewritten: string[];
  skipped: string[];
}

export function attach(configPath: string, opts: AttachOptions): AttachResult {
  if (!existsSync(configPath)) throw new Error(`config not found: ${configPath}`);
  if (isAttached(configPath)) throw new Error(`already attached: ${configPath} (detach first)`);

  const original = readFileSync(configPath);
  const doc = JSON.parse(original.toString('utf8')) as Record<string, unknown>;
  const servers = serversBlock(doc);
  if (!servers) throw new Error(`no mcpServers block in ${configPath}`);

  // Backup FIRST. Nothing below may run before this file exists on disk.
  const backupPath = backupPathFor(configPath);
  if (existsSync(backupPath)) {
    throw new Error(`refusing to overwrite an existing backup: ${backupPath}`);
  }
  writeFileSync(backupPath, original, { mode: 0o600 });
  // Prove it landed before proceeding.
  if (!existsSync(backupPath) || statSync(backupPath).size !== original.length) {
    throw new Error(`backup did not write correctly: ${backupPath}`);
  }

  const node = opts.nodePath ?? process.execPath;
  const rewritten: string[] = [];
  const skipped: string[] = [];

  for (const [name, entry] of Object.entries(servers)) {
    if (!entry || typeof entry !== 'object' || typeof entry.command !== 'string') {
      // Remote (url) servers have no stdio to sit in front of.
      skipped.push(name);
      continue;
    }
    const inner = { command: entry.command, args: entry.args ?? [] };
    servers[name] = {
      ...entry,
      command: node,
      args: [
        opts.shimPath,
        '--log', opts.logDir,
        '--name', name,
        ...(opts.signingKeyPath !== undefined ? ['--key', opts.signingKeyPath] : []),
        ...(opts.witnessFile !== undefined ? ['--witness', opts.witnessFile] : []),
        '--', inner.command, ...inner.args,
      ],
      [SHIM_MARKER]: { version: 1, original: inner },
    };
    rewritten.push(name);
  }

  // Write via a temp file and rename, so a crash cannot leave a half-written
  // config that starts nothing.
  const tmp = `${configPath}.orisan-tmp`;
  writeFileSync(tmp, `${JSON.stringify(doc, null, 2)}\n`);
  renameSync(tmp, configPath);

  return { configPath, backupPath, rewritten, skipped };
}

export interface DetachResult {
  configPath: string;
  restoredFrom: string;
  byteIdentical: boolean;
}

export function detach(configPath: string): DetachResult {
  const backupPath = backupPathFor(configPath);
  if (!existsSync(backupPath)) throw new Error(`no backup to restore: ${backupPath}`);

  const backup = readFileSync(backupPath);
  copyFileSync(backupPath, configPath);
  const restored = readFileSync(configPath);
  const byteIdentical = backup.equals(restored);
  if (!byteIdentical) {
    throw new Error(`restore did not reproduce the original bytes for ${configPath}`);
  }
  // Only remove the backup once the restore is proven.
  writeFileSync(backupPath, backup);
  return { configPath, restoredFrom: backupPath, byteIdentical };
}

/** Remove the backup after a verified detach. Separate so detach stays reversible. */
export function discardBackup(configPath: string): void {
  const backupPath = backupPathFor(configPath);
  if (existsSync(backupPath)) rmSync(backupPath, { force: true });
}

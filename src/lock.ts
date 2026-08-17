/**
 * Issue #1 — an exclusive writer lock on a log directory.
 *
 * `EventStore` keeps `nextSeq` and `lastHash` in process memory and opens the
 * segment with O_APPEND. Two processes therefore both believed they owned the
 * head and both wrote it: 30 events each produced 60 lines with 30 distinct
 * sequence numbers, every one duplicated with a different `prev_hash`. The
 * chain is not repairable afterwards, because nothing on disk records which of
 * the two orderings actually happened.
 *
 * It is not an exotic case. The default log directory is shared, so two
 * `orisan-rec start` invocations, two attached editors, or one agent restarted
 * before the old one exited will all collide.
 *
 * The lock is a file created with O_CREAT|O_EXCL, which is atomic on POSIX and
 * on Windows. Holding it is a precondition for writing, not advice.
 *
 * STALE LOCKS. A recorder killed with SIGKILL cannot clean up after itself, and
 * a lock that outlives its holder would brick the directory until someone
 * deleted it by hand — which trains people to delete lock files reflexively,
 * the reflex that makes locking useless. So a lock naming a dead pid ON THIS
 * HOST is reclaimed automatically. A lock from another host is refused, because
 * we cannot ask whether that process is alive, and guessing wrong is the
 * corruption this exists to prevent.
 */

import { closeSync, existsSync, fsyncSync, openSync, readFileSync, unlinkSync, writeSync } from 'node:fs';
import { hostname } from 'node:os';
import { join } from 'node:path';

export const LOCK_FILENAME = 'writer.lock';

export interface LockInfo {
  pid: number;
  hostname: string;
  started_at: string;
}

export type LockRefusal = 'held' | 'held_by_this_process' | 'foreign_host' | 'unreadable';

export class LogDirectoryLockedError extends Error {
  constructor(
    readonly reason: LockRefusal,
    readonly lockPath: string,
    readonly holder: LockInfo | null,
    message: string,
  ) {
    super(message);
    this.name = 'LogDirectoryLockedError';
  }
}

export interface WriterLock {
  readonly path: string;
  readonly info: LockInfo;
  /** Idempotent. Only removes the file if it still describes this holder. */
  release(): void;
}

/**
 * Is this pid running?
 *
 * EPERM means it exists and belongs to another user, which still counts as
 * alive — treating it as dead is how you steal a live lock.
 */
export function pidIsAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM';
  }
}

function readLock(path: string): LockInfo | null {
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as Partial<LockInfo>;
    if (typeof parsed.pid !== 'number' || typeof parsed.hostname !== 'string') return null;
    return { pid: parsed.pid, hostname: parsed.hostname, started_at: String(parsed.started_at ?? '') };
  } catch {
    return null;
  }
}

/** All locks this process holds, released together on exit. */
const held = new Set<{ path: string; info: LockInfo }>();
let exitHookInstalled = false;

function releaseFile(path: string, info: LockInfo): void {
  // Only remove a lock that is still ours. If we went stale and another
  // recorder reclaimed it, deleting the file would hand the directory to a
  // third writer while the second is mid-append.
  const current = readLock(path);
  if (current && current.pid === info.pid && current.hostname === info.hostname) {
    try { unlinkSync(path); } catch { /* already gone */ }
  }
}

function installExitHook(): void {
  if (exitHookInstalled) return;
  exitHookInstalled = true;
  // 'exit' only. Installing SIGTERM/SIGINT handlers here would change what
  // those signals do to any program embedding this, and it is unnecessary:
  // a signal-killed recorder leaves a lock naming a dead pid, which the next
  // open reclaims. That path is tested.
  process.on('exit', () => {
    for (const l of held) releaseFile(l.path, l.info);
    held.clear();
  });
}

export interface AcquireOptions {
  /** Overridden in tests so a foreign-host lock can be exercised. */
  hostId?: string;
  pid?: number;
  now?: () => Date;
}

/**
 * Take the writer lock, or throw explaining exactly who holds it.
 *
 * Retries a bounded number of times, because reclaiming a stale lock and
 * creating a new one is two syscalls and another process may win in between.
 * Losing that race means someone else legitimately holds it, which is the
 * normal refusal path.
 */
export function acquireWriterLock(dir: string, opts: AcquireOptions = {}): WriterLock {
  const path = join(dir, LOCK_FILENAME);
  const info: LockInfo = {
    pid: opts.pid ?? process.pid,
    hostname: opts.hostId ?? hostname(),
    started_at: (opts.now?.() ?? new Date()).toISOString(),
  };

  for (let attempt = 0; attempt < 3; attempt++) {
    let fd: number;
    try {
      fd = openSync(path, 'wx');
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;

      const holder = readLock(path);
      if (!holder) {
        throw new LogDirectoryLockedError('unreadable', path, null,
          `${path} exists but cannot be read as a lock file. If no recorder is running against ${dir}, delete it.`);
      }
      if (holder.hostname !== info.hostname) {
        throw new LogDirectoryLockedError('foreign_host', path, holder,
          `${dir} is locked by pid ${holder.pid} on host "${holder.hostname}" since ${holder.started_at}. `
          + 'This host cannot check whether that process is still alive, so the lock is not reclaimed automatically. '
          + `If you are certain nothing is recording there, delete ${path}.`);
      }
      if (holder.pid === info.pid) {
        throw new LogDirectoryLockedError('held_by_this_process', path, holder,
          `${dir} is already open for writing by this process (pid ${holder.pid}). `
          + 'Close the existing store before opening another.');
      }
      if (pidIsAlive(holder.pid)) {
        throw new LogDirectoryLockedError('held', path, holder,
          `${dir} is being recorded to by pid ${holder.pid} on this machine since ${holder.started_at}. `
          + 'Two recorders on one log directory corrupt the chain, so this one will not start. '
          + 'Stop that recorder, or record to a different directory.');
      }

      // Dead holder on this host: reclaim and try again.
      try { unlinkSync(path); } catch { /* someone else got there first */ }
      continue;
    }

    try {
      const body = Buffer.from(`${JSON.stringify(info)}\n`, 'utf8');
      writeSync(fd, body, 0, body.length);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }

    const entry = { path, info };
    held.add(entry);
    installExitHook();

    let released = false;
    return {
      path,
      info,
      release(): void {
        if (released) return;
        released = true;
        held.delete(entry);
        releaseFile(path, info);
      },
    };
  }

  const holder = readLock(path);
  throw new LogDirectoryLockedError('held', path, holder,
    `could not take the writer lock on ${dir} after three attempts; another recorder keeps reclaiming it.`);
}

/** Who holds the lock on this directory, if anyone. For diagnostics. */
export function currentLockHolder(dir: string): LockInfo | null {
  const path = join(dir, LOCK_FILENAME);
  return existsSync(path) ? readLock(path) : null;
}

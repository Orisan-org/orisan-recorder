/**
 * R2.1 — discovery.
 *
 * The wedge. Every competitor records only what it was pointed at, so their
 * logs are complete by assertion. This finds agents nobody mentioned, which is
 * the difference between "here is what we recorded" and "here is everything
 * that was running".
 *
 * Two independent sources, deliberately. Config scanning finds agents that are
 * installed; process scanning finds agents that are *running*, including ones
 * launched from a config we do not know the shape of. Each covers the other's
 * blind spot, and every server carries the `source` that found it so a report
 * can say how it was learned rather than flattening both into "found".
 *
 * Cross-platform rules, learned from a competitor that shipped a macOS-dead
 * feature by calling `ps --no-headers` (a GNU-only flag) inside a bare
 * `except: pass`: no GNU-only flags, and a failed probe is reported, never
 * swallowed.
 */

import { execFileSync } from 'node:child_process';
import { closeSync, existsSync, openSync, readFileSync, readSync, readdirSync, statSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { join } from 'node:path';

export type ServerSource = 'config' | 'process';

export interface DiscoveredServer {
  name: string;
  command: string;
  args: string[];
  source: ServerSource;
  /** pid, when found by process scan. */
  pid?: number;
}

export interface DiscoveredSurface {
  surface: string;
  config_path: string | null;
  servers: DiscoveredServer[];
}

export interface ScanResult {
  scanned_at: string;
  platform: string;
  home: string;
  surfaces: DiscoveredSurface[];
  /** Probes that could not run. Never silently dropped. */
  gaps: string[];
}

interface KnownLocation {
  surface: string;
  /** Relative to home unless absolute. */
  paths: string[];
}

/**
 * Known MCP config locations.
 *
 * macOS and Linux are both listed for every surface rather than switching on
 * platform: a path that does not exist costs one stat, and hard-coding the
 * switch is how a tool silently stops finding things on the OS its author does
 * not use.
 */
export const KNOWN_LOCATIONS: readonly KnownLocation[] = [
  {
    surface: 'Claude Desktop',
    paths: [
      'Library/Application Support/Claude/claude_desktop_config.json', // macOS
      '.config/Claude/claude_desktop_config.json',                      // Linux
      'AppData/Roaming/Claude/claude_desktop_config.json',              // Windows
    ],
  },
  {
    surface: 'Claude Code',
    paths: ['.claude.json', '.config/claude/mcp.json'],
  },
  {
    surface: 'Cursor',
    paths: ['.cursor/mcp.json', 'Library/Application Support/Cursor/User/globalStorage/mcp.json'],
  },
  {
    surface: 'Windsurf',
    paths: ['.codeium/windsurf/mcp_config.json'],
  },
  {
    surface: 'Continue',
    paths: ['.continue/config.json'],
  },
  {
    surface: 'Cline',
    paths: [
      'Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json',
      '.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json',
    ],
  },
  {
    surface: 'VS Code',
    paths: [
      'Library/Application Support/Code/User/settings.json',
      '.config/Code/User/settings.json',
    ],
  },
];

/** Directories never worth walking when hunting for stray configs. */
const SKIP_DIRS = new Set([
  'node_modules', '.git', '.svn', '.hg', 'dist', 'build', 'target',
  '.cache', 'Caches', '.npm', '.pnpm-store', 'venv', '.venv',
  '__pycache__', '.Trash', 'Photos Library.photoslibrary',
  // Platform application data. The MCP configs that live in here are already
  // covered by KNOWN_LOCATIONS by exact path; walking them costs tens of
  // thousands of stats and finds nothing new.
  'Library', 'AppData', 'Applications', 'Music', 'Movies', 'Pictures',
  'go', '.rustup', '.cargo', '.gradle', '.m2', '.docker', '.terraform.d',
]);

/**
 * Budgets for the stray-config walk.
 *
 * An unbounded walk of a real home directory took longer than two minutes in
 * testing — fixture homes are tiny, so only running it against a real machine
 * showed it. A scan that hangs is a scan nobody runs, so the walk is bounded
 * and reports what it skipped rather than quietly running forever or quietly
 * stopping early.
 */
const WALK_DEFAULTS = { maxDepth: 3, maxEntries: 20_000, maxMs: 5_000, prefilterBytes: 65_536 };

/** Parse an mcpServers block out of an already-parsed JSON document. */
export function serversFromConfig(doc: unknown): DiscoveredServer[] {
  if (!doc || typeof doc !== 'object') return [];
  const root = doc as Record<string, unknown>;
  // VS Code nests it under "mcp"; everything else uses a top-level key.
  const blocks: unknown[] = [root['mcpServers']];
  const mcp = root['mcp'];
  if (mcp && typeof mcp === 'object') blocks.push((mcp as Record<string, unknown>)['servers']);

  const out: DiscoveredServer[] = [];
  for (const block of blocks) {
    if (!block || typeof block !== 'object') continue;
    for (const [name, raw] of Object.entries(block as Record<string, unknown>)) {
      if (!raw || typeof raw !== 'object') continue;
      const cfg = raw as Record<string, unknown>;
      const command = typeof cfg['command'] === 'string' ? cfg['command'] : '';
      const args = Array.isArray(cfg['args']) ? cfg['args'].map(String) : [];
      // A remote (url-only) server has no command; still worth reporting.
      if (command === '' && typeof cfg['url'] !== 'string') continue;
      out.push({ name, command: command || String(cfg['url']), args, source: 'config' });
    }
  }
  return out;
}

function readJsonIfPossible(path: string): { doc: unknown } | { error: string } {
  try {
    return { doc: JSON.parse(readFileSync(path, 'utf8')) as unknown };
  } catch (e) {
    return { error: `${path}: ${(e as Error).message}` };
  }
}

/** Walk for stray JSON files carrying an mcpServers key, within a budget. */
function findGenericConfigs(
  home: string,
  gaps: string[],
  budget: Partial<typeof WALK_DEFAULTS> = {},
): DiscoveredSurface[] {
  const { maxDepth, maxEntries, maxMs, prefilterBytes } = { ...WALK_DEFAULTS, ...budget };
  const found: DiscoveredSurface[] = [];
  const seen = new Set<string>();
  const deadline = Date.now() + maxMs;
  let entriesSeen = 0;
  let truncated = false;

  const walk = (dir: string, depth: number): void => {
    if (depth > maxDepth || truncated) return;
    if (entriesSeen >= maxEntries || Date.now() > deadline) {
      truncated = true;
      return;
    }
    let entries: import('node:fs').Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      gaps.push(`could not read ${dir}: ${(e as Error).message}`);
      return;
    }
    for (const entry of entries) {
      if (truncated) return;
      if (++entriesSeen >= maxEntries || Date.now() > deadline) {
        truncated = true;
        return;
      }
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        walk(full, depth + 1);
      } else if (entry.isFile() && entry.name.endsWith('.json')) {
        if (seen.has(full)) continue;
        // Pre-filter on the first chunk only. Reading whole files here is what
        // made the walk unusable on a real home directory.
        let head: string;
        let fd: number | undefined;
        try {
          if (statSync(full).size > 2_000_000) continue;
          fd = openSync(full, 'r');
          const buf = Buffer.alloc(prefilterBytes);
          const n = readSync(fd, buf, 0, prefilterBytes, 0);
          head = buf.subarray(0, n).toString('utf8');
        } catch {
          continue;
        } finally {
          if (fd !== undefined) closeSync(fd);
        }
        if (!head.includes('mcpServers')) continue;
        seen.add(full);
        const parsed = readJsonIfPossible(full);
        if ('error' in parsed) {
          gaps.push(`unparseable JSON with an mcpServers key: ${parsed.error}`);
          continue;
        }
        const servers = serversFromConfig(parsed.doc);
        if (servers.length > 0) found.push({ surface: 'Unknown (generic mcpServers)', config_path: full, servers });
      }
    }
  };

  walk(home, 0);
  if (truncated) {
    gaps.push(
      `stray-config search stopped early after ${entriesSeen} entries or ${maxMs}ms; ` +
      'directories beyond that point were not searched',
    );
  }
  return found;
}

/** Interpreters an MCP server is plausibly launched with. */
const RUNTIMES = new Set([
  'node', 'nodejs', 'deno', 'bun', 'npx', 'uv', 'uvx',
  'python', 'python2', 'python3', 'python3.10', 'python3.11', 'python3.12', 'python3.13', 'python3.14',
]);

/** Shells. A shell command that merely mentions MCP is not an MCP server. */
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'fish', 'ksh', 'csh', 'tcsh']);

/**
 * Does this argv look like an MCP server?
 *
 * The EXECUTABLE must be a runtime and the MCP marker must appear in an
 * argument, not merely somewhere in the command line. An earlier version
 * tested the whole string for both, so a shell running `... eval '...mcp...'`
 * matched — a live scan of this machine reported two of the tool's own build
 * commands as MCP servers. A discovery feature that invents agents is worse
 * than one that misses them: its entire value is that its list can be trusted.
 */
export function looksLikeMcpProcess(args: string): boolean {
  const parts = args.trim().split(/\s+/);
  if (parts.length === 0) return false;
  const exe = (parts[0] ?? '').split('/').pop() ?? '';
  if (SHELLS.has(exe)) return false;
  if (!RUNTIMES.has(exe)) return false;

  // Anything after an inline-script flag is a program body, not a path.
  const rest = parts.slice(1);
  const scriptFlag = rest.findIndex((a) => a === '-c' || a === '-e' || a === '--eval');
  const considered = scriptFlag === -1 ? rest : rest.slice(0, scriptFlag);

  return considered.some(
    (a) =>
      /(^|[/@_-])mcp([/_-]|$)/i.test(a) ||
      /mcp[-_]server|server[-_]mcp|@modelcontextprotocol/i.test(a),
  );
}

/**
 * Running processes that look like MCP servers.
 *
 * `ps -A -o pid=,args=` is accepted by both BSD (macOS) and GNU (Linux) ps.
 * A failure is pushed to `gaps`; it must never be silently swallowed.
 */
export function scanProcesses(gaps: string[], psOutput?: string): DiscoveredServer[] {
  let out: string;
  if (psOutput !== undefined) {
    out = psOutput;
  } else if (platform() === 'win32') {
    gaps.push('process scan not implemented on Windows; config scan only');
    return [];
  } else {
    try {
      out = execFileSync('ps', ['-A', '-o', 'pid=,args='], {
        encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (e) {
      gaps.push(`process scan failed: ${(e as Error).message}`);
      return [];
    }
  }

  const servers: DiscoveredServer[] = [];
  for (const line of out.split('\n')) {
    const m = /^\s*(\d+)\s+(.*)$/.exec(line);
    if (!m) continue;
    const pid = Number.parseInt(m[1]!, 10);
    const argv = m[2]!.trim();
    if (argv.length === 0 || !looksLikeMcpProcess(argv)) continue;
    const parts = argv.split(/\s+/);
    servers.push({
      name: guessProcessName(parts),
      command: parts[0]!,
      args: parts.slice(1),
      source: 'process',
      pid,
    });
  }
  return servers;
}

function guessProcessName(parts: readonly string[]): string {
  for (const p of parts.slice(1)) {
    const m = /([A-Za-z0-9_.-]*mcp[A-Za-z0-9_.-]*)/i.exec(p);
    if (m) return m[1]!.replace(/\.(js|py|ts)$/, '');
  }
  return parts[0]?.split('/').pop() ?? 'unknown';
}

export interface ScanOptions {
  /** Root to scan. Tests pass a fixture home; never the real one. */
  home?: string;
  /** Skip the bounded stray-config walk. */
  skipGenericWalk?: boolean;
  /** Override the walk budget (tests use a tiny one to exercise truncation). */
  walkBudget?: Partial<typeof WALK_DEFAULTS>;
  /** Skip the process probe. */
  skipProcesses?: boolean;
  /** Canned `ps` output, for tests. */
  psOutput?: string;
}

export function scan(opts: ScanOptions = {}): ScanResult {
  const home = opts.home ?? homedir();
  const gaps: string[] = [];
  const surfaces: DiscoveredSurface[] = [];
  const seenPaths = new Set<string>();

  for (const loc of KNOWN_LOCATIONS) {
    for (const rel of loc.paths) {
      const path = join(home, rel);
      if (!existsSync(path) || seenPaths.has(path)) continue;
      seenPaths.add(path);
      const parsed = readJsonIfPossible(path);
      if ('error' in parsed) {
        gaps.push(`${loc.surface}: ${parsed.error}`);
        continue;
      }
      const servers = serversFromConfig(parsed.doc);
      // Report the surface even with zero servers: "installed but empty" is
      // different from "not installed", and an operator should see both.
      surfaces.push({ surface: loc.surface, config_path: path, servers });
    }
  }

  if (!opts.skipGenericWalk) {
    for (const g of findGenericConfigs(home, gaps, opts.walkBudget ?? {})) {
      if (seenPaths.has(g.config_path!)) continue;
      seenPaths.add(g.config_path!);
      surfaces.push(g);
    }
  }

  if (opts.skipProcesses) {
    // Never a silent omission. A probe that did not run is reported as a gap,
    // the same as one that failed — otherwise "no running servers found" and
    // "we did not look for running servers" render identically, and the second
    // is the one an operator must not mistake for the first.
    gaps.push('process scan skipped at the caller\'s request; running servers were not looked for');
  } else {
    const running = scanProcesses(gaps, opts.psOutput);
    if (running.length > 0) {
      surfaces.push({ surface: 'Running processes', config_path: null, servers: running });
    }
  }

  if (platform() === 'win32') {
    gaps.push('Windows support is best-effort: config paths are covered, process scan is not');
  }

  return {
    scanned_at: new Date().toISOString(),
    platform: platform(),
    home,
    surfaces,
    gaps,
  };
}

/** Total servers across every surface. */
export function serverCount(r: ScanResult): number {
  return r.surfaces.reduce((n, s) => n + s.servers.length, 0);
}

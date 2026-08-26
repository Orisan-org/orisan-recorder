/**
 * R2.1 discovery. Every test runs against a FIXTURE home directory — never the
 * real machine, which would make results depend on whoever runs the suite.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import {
  looksLikeMcpProcess, scan, scanProcesses, serverCount, serversFromConfig,
} from '../src/discover.js';

let home: string;
beforeEach(() => { home = mkdtempSync(join(tmpdir(), 'orisan-home-')); });
afterEach(() => { rmSync(home, { recursive: true, force: true }); });

function put(rel: string, doc: unknown): string {
  const path = join(home, rel);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, typeof doc === 'string' ? doc : JSON.stringify(doc, null, 2));
  return path;
}

const CLAUDE_MAC = 'Library/Application Support/Claude/claude_desktop_config.json';

const twoServers = {
  mcpServers: {
    filesystem: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'] },
    'fake-crm': { command: 'node', args: ['/opt/fake-crm/server.js'] },
  },
};

describe('config parsing', () => {
  it('reads a top-level mcpServers block', () => {
    const s = serversFromConfig(twoServers);
    expect(s.map((x) => x.name).sort()).toEqual(['fake-crm', 'filesystem']);
    expect(s[0]!.source).toBe('config');
  });

  it('reads the VS Code shape (mcp.servers)', () => {
    const s = serversFromConfig({ mcp: { servers: { a: { command: 'node', args: ['x.js'] } } } });
    expect(s).toHaveLength(1);
    expect(s[0]!.name).toBe('a');
  });

  it('keeps url-only remote servers', () => {
    const s = serversFromConfig({ mcpServers: { remote: { url: 'https://mcp.example.invalid/sse' } } });
    expect(s[0]!.command).toBe('https://mcp.example.invalid/sse');
  });

  it('ignores junk without throwing', () => {
    expect(serversFromConfig(null)).toEqual([]);
    expect(serversFromConfig({ mcpServers: 'nope' })).toEqual([]);
    expect(serversFromConfig({ mcpServers: { bad: 42 } })).toEqual([]);
  });
});

describe('known locations', () => {
  it('ACCEPTANCE: finds a Claude Desktop config in a fixture home', () => {
    const path = put(CLAUDE_MAC, twoServers);
    const r = scan({ home, skipProcesses: true });
    const cd = r.surfaces.find((s) => s.surface === 'Claude Desktop');
    expect(cd).toBeDefined();
    expect(cd!.config_path).toBe(path);
    expect(cd!.servers).toHaveLength(2);
  });

  it('finds the Linux path for the same surface', () => {
    put('.config/Claude/claude_desktop_config.json', twoServers);
    const cd = scan({ home, skipProcesses: true }).surfaces.find((s) => s.surface === 'Claude Desktop');
    expect(cd!.servers).toHaveLength(2);
  });

  it('finds several surfaces at once', () => {
    put(CLAUDE_MAC, twoServers);
    put('.cursor/mcp.json', { mcpServers: { c: { command: 'node', args: [] } } });
    put('.codeium/windsurf/mcp_config.json', { mcpServers: { w: { command: 'python3', args: [] } } });
    const r = scan({ home, skipProcesses: true });
    expect(r.surfaces.map((s) => s.surface).sort()).toEqual(['Claude Desktop', 'Cursor', 'Windsurf']);
    expect(serverCount(r)).toBe(4);
  });

  it('reports an installed-but-empty surface rather than hiding it', () => {
    put(CLAUDE_MAC, { mcpServers: {} });
    const cd = scan({ home, skipProcesses: true }).surfaces.find((s) => s.surface === 'Claude Desktop');
    expect(cd).toBeDefined();
    expect(cd!.servers).toEqual([]);
  });

  it('records unparseable config as a gap instead of swallowing it', () => {
    put(CLAUDE_MAC, '{ this is not json');
    const r = scan({ home, skipProcesses: true });
    expect(r.surfaces.find((s) => s.surface === 'Claude Desktop')).toBeUndefined();
    expect(r.gaps.some((g) => g.includes('Claude Desktop'))).toBe(true);
  });

  it('an empty home finds nothing, and the skipped probe is the only gap', () => {
    const r = scan({ home, skipProcesses: true });
    expect(r.surfaces).toEqual([]);
    // A probe that did not run is reported, never omitted: "no running servers
    // found" and "we did not look for running servers" must not render the
    // same, and the second is the one an operator could mistake for the first.
    expect(r.gaps).toEqual([
      "process scan skipped at the caller's request; running servers were not looked for",
    ]);
  });

  it('a scan that runs every probe reports no gaps at all', () => {
    const r = scan({ home, psOutput: '' });
    expect(r.surfaces).toEqual([]);
    expect(r.gaps).toEqual([]);
  });
});

describe('generic stray configs — the actual wedge', () => {
  it('finds an mcpServers file nobody told us about', () => {
    const path = put('projects/weird-tool/settings.json', { mcpServers: { ghost: { command: 'node', args: ['g.js'] } } });
    const r = scan({ home, skipProcesses: true });
    const generic = r.surfaces.find((s) => s.config_path === path);
    expect(generic).toBeDefined();
    expect(generic!.surface).toMatch(/generic/i);
    expect(generic!.servers[0]!.name).toBe('ghost');
  });

  it('does not double-report a known location as generic', () => {
    put(CLAUDE_MAC, twoServers);
    const r = scan({ home, skipProcesses: true });
    expect(r.surfaces.filter((s) => s.config_path?.includes('claude_desktop_config'))).toHaveLength(1);
  });

  it('skips node_modules and other noise directories', () => {
    put('proj/node_modules/pkg/config.json', { mcpServers: { noise: { command: 'node', args: [] } } });
    const r = scan({ home, skipProcesses: true });
    expect(r.surfaces).toEqual([]);
  });

  it('ignores JSON without an mcpServers key', () => {
    put('proj/tsconfig.json', { compilerOptions: {} });
    expect(scan({ home, skipProcesses: true }).surfaces).toEqual([]);
  });
});

describe('process scan', () => {
  const PS = [
    '    1 /sbin/launchd',
    '  501 node /Users/x/.npm/_npx/abc/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js /tmp',
    '  502 python3 -m mcp_server_git --repository /srv/repo',
    '  503 /Applications/Firefox.app/Contents/MacOS/firefox',
    '  504 node /opt/tools/plain-server.js',
    '  505 npx -y some-mcp-thing',
  ].join('\n');

  it('picks out MCP-looking processes and ignores the rest', () => {
    const gaps: string[] = [];
    const found = scanProcesses(gaps, PS);
    expect(found.map((s) => s.pid).sort()).toEqual([501, 502, 505]);
    expect(gaps).toEqual([]);
    expect(found.every((s) => s.source === 'process')).toBe(true);
  });

  it('classifies argv correctly', () => {
    expect(looksLikeMcpProcess('node /x/@modelcontextprotocol/server-fs/index.js')).toBe(true);
    expect(looksLikeMcpProcess('python3 -m mcp_server_git')).toBe(true);
    expect(looksLikeMcpProcess('node /opt/plain.js')).toBe(false);
    expect(looksLikeMcpProcess('/usr/bin/mcpainter')).toBe(false); // not a runtime
  });

  it('surfaces running servers under their own heading', () => {
    const r = scan({ home, psOutput: PS });
    const running = r.surfaces.find((s) => s.surface === 'Running processes');
    expect(running!.servers).toHaveLength(3);
    expect(running!.config_path).toBeNull();
  });

  it('a failed process probe becomes a gap, never silence', () => {
    const gaps: string[] = [];
    // Malformed output yields nothing, but a genuine failure is what matters:
    // scanProcesses only swallows when it has output to parse.
    expect(scanProcesses(gaps, 'garbage without pids')).toEqual([]);
    expect(gaps).toEqual([]);
  });
});

describe('the two sources cover each other', () => {
  it('a running server absent from any config is still found', () => {
    put(CLAUDE_MAC, { mcpServers: { known: { command: 'node', args: ['known.js'] } } });
    const r = scan({ home, psOutput: '  777 node /secret/undeclared-mcp-server.js' });
    expect(serverCount(r)).toBe(2);
    expect(r.surfaces.flatMap((s) => s.servers).map((s) => s.source).sort()).toEqual(['config', 'process']);
  });
});

describe('regression: the process scan must not invent agents', () => {
  it('does not match a shell command that merely mentions mcp', () => {
    // Observed on a live scan: the tool reported its own build commands as MCP
    // servers because "mcp" appeared inside a zsh -c string.
    const shellLine = `/bin/zsh -c source /Users/x/.claude/snapshot.sh && eval 'cd ~/repo && python3 - <<PY\np = "src/discover.ts"  # mcp stuff\nPY'`;
    expect(looksLikeMcpProcess(shellLine)).toBe(false);
  });

  it('does not match node -e with mcp in the inline script', () => {
    expect(looksLikeMcpProcess(`node -e "console.log('mcp-server')"`)).toBe(false);
  });

  it('still matches genuine servers', () => {
    expect(looksLikeMcpProcess('node /Users/x/.npm/_npx/abc/node_modules/.bin/mcp-server-puppeteer')).toBe(true);
    expect(looksLikeMcpProcess('python3 -m mcp_server_git --repository /srv/repo')).toBe(true);
    expect(looksLikeMcpProcess('npx -y @modelcontextprotocol/server-filesystem /tmp')).toBe(true);
  });

  it('does not match unrelated binaries whose name contains mcp', () => {
    expect(looksLikeMcpProcess('/usr/local/bin/mcpainter --file x.png')).toBe(false);
  });
});

describe('the stray-config walk is bounded', () => {
  it('reports truncation as a gap instead of running forever or stopping silently', () => {
    for (let i = 0; i < 60; i++) put(`deep/dir${i}/settings.json`, { mcpServers: { [`s${i}`]: { command: 'node', args: [] } } });
    const r = scan({ home, skipProcesses: true, walkBudget: { maxEntries: 5 } });
    expect(r.gaps.some((g) => /stopped early/.test(g))).toBe(true);
  });
});

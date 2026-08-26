/**
 * Committed media must not carry the recorder author's machine.
 *
 * The first published showcase opened on a real `orisan-rec scan`: username,
 * every installed MCP client, an unrelated project directory, the Orisan
 * working layout, and live process ids. It was true — that was the point of
 * recording a real machine — and it was an inventory of its owner on the front
 * page of a security tool.
 *
 * WHAT THIS CAN AND CANNOT CHECK. The `.cast` is text and is checked directly.
 * The `.gif` is rendered FROM that cast and the `.png`s are screenshots, so
 * their text is pixels and no byte scan can read it. Those are covered
 * transitively: the cast is the GIF's only source, and media/README.md records
 * the fabricated root the screenshots were captured against. A byte scan is
 * still run over every media file, because an image can carry text in metadata.
 *
 * This is a guard against the specific regression, not proof that no image
 * anywhere shows something private. Re-capturing images is a human act with a
 * human check.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { homedir, userInfo } from 'node:os';
import { basename, join } from 'node:path';

const MEDIA = join(import.meta.dirname, '..', 'media');

/** Fabricated roots the published artefacts are allowed to show. */
const ALLOWED_USERS = new Set(['demo']);

function mediaFiles(): string[] {
  return readdirSync(MEDIA).filter((f) => !f.startsWith('.'));
}

function tracked(file: string): boolean {
  const out = execFileSync('git', ['ls-files', '--error-unmatch', join('media', file)], {
    cwd: join(import.meta.dirname, '..'),
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  return out.trim().length > 0;
}

describe('committed media carries no real identity', () => {
  it('finds media to check, so this cannot pass vacuously', () => {
    const files = mediaFiles();
    expect(files.length).toBeGreaterThan(5);
    expect(files).toContain('showcase.cast');
    expect(files).toContain('showcase.gif');
  });

  it('no media file contains this machine\'s home directory', () => {
    const home = Buffer.from(homedir(), 'utf8');
    const offenders = mediaFiles().filter((f) => readFileSync(join(MEDIA, f)).includes(home));
    expect(offenders, `${homedir()} appears in: ${offenders.join(', ')}`).toEqual([]);
  });

  it('no media file contains this machine\'s username', () => {
    // Skipped for a username so short it would match by accident; the home
    // path check above still covers the real case.
    const user = userInfo().username;
    if (user.length < 4) return;
    const needle = Buffer.from(user, 'utf8');
    const offenders = mediaFiles().filter((f) => readFileSync(join(MEDIA, f)).includes(needle));
    expect(offenders, `username "${user}" appears in: ${offenders.join(', ')}`).toEqual([]);
  });

  it('the cast shows no home path other than a fabricated one', () => {
    const cast = readFileSync(join(MEDIA, 'showcase.cast'), 'utf8');
    const users = [...cast.matchAll(/\/(?:Users|home)\/([A-Za-z0-9._-]+)/g)].map((m) => m[1]!);
    const real = [...new Set(users)].filter((u) => !ALLOWED_USERS.has(u));
    expect(real, `unexpected home directories in the cast: ${real.join(', ')}`).toEqual([]);
  });

  it('the cast records no process ids, which are machine-specific', () => {
    const cast = readFileSync(join(MEDIA, 'showcase.cast'), 'utf8');
    expect(cast).not.toMatch(/\[pid \d+\]/);
    expect(cast).not.toContain('_npx/');
  });

  it('the cast states that discovery ran against a fabricated root', () => {
    // The substitution has to be visible to a viewer, not just true. A demo
    // that quietly swaps its input is the thing this project exists not to be.
    const cast = readFileSync(join(MEDIA, 'showcase.cast'), 'utf8');
    expect(cast).toContain('fabricated home directory');
    expect(cast).toMatch(/scan.{0,40}with no arguments to read yours/s);
  });

  it('the cast reports the probe it skipped rather than omitting it', () => {
    const cast = readFileSync(join(MEDIA, 'showcase.cast'), 'utf8');
    expect(cast).toContain('process scan skipped');
  });

  it('the recording is of a passing run', () => {
    expect(readFileSync(join(MEDIA, 'showcase.cast'), 'utf8')).not.toContain('SHOWCASE FAILED');
  });

  it('every media file is tracked, so nothing checked here is a local stray', () => {
    for (const file of mediaFiles()) {
      expect(() => tracked(file), `${file} is untracked`).not.toThrow();
    }
  });

  it('media/README.md names the fabricated root the images were captured against', () => {
    const readme = readFileSync(join(MEDIA, 'README.md'), 'utf8');
    expect(readme).toMatch(/fabricat|fixture/i);
    expect(readme).toContain('demo-home');
  });
});

describe('the fixture home the demo scans', () => {
  const FIXTURE = join(import.meta.dirname, 'fixtures', 'demo-home');

  it('contains no reference to the real machine', () => {
    const walk = (dir: string): string[] =>
      readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
        e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)],
      );
    const home = homedir();
    for (const file of walk(FIXTURE)) {
      const text = readFileSync(file, 'utf8');
      expect(text, `${basename(file)} references the real home`).not.toContain(home);
    }
  });

  it('says in writing that it is fabricated', () => {
    expect(readFileSync(join(FIXTURE, 'README.md'), 'utf8')).toMatch(/fabricated/i);
  });
});

import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    globalSetup: ['test/global-setup.ts'],
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
  resolve: {
    alias: {
      // The witness is a sibling REPOSITORY, not a dependency of this one: it
      // is unpublished, so a public clone will not have it and must still run
      // green. Resolved by relative path rather than through node_modules, so
      // no `file:` entry in package.json can fail a clone's install. The suites
      // that need it skip when it is absent — see test/fixtures/witness-fixture.ts.
      'orisan-witness/src': join(here, '..', 'orisan-witness', 'src'),
    },
  },
});

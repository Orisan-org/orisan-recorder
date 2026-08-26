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
  // No alias for the witness sibling: test/fixtures/witness-fixture.ts imports
  // it by absolute file URL when it is present, and skips its suites when it
  // is not. An alias would only matter for a bare specifier, and a bare
  // specifier is what tsc would try to resolve in a clone that has no sibling.
});

import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
  resolve: {
    alias: {
      // The witness is a sibling repo; tests exercise the real service, not a
      // mock, so its TypeScript sources are resolved directly.
      'orisan-witness/src': join(here, 'node_modules', 'orisan-witness', 'src'),
    },
  },
});

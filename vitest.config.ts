import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // Crash-recovery tests spawn child processes and kill -9 them.
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});

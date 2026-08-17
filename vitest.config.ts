import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    coverage: {
      enabled: false,
    },
    hookTimeout: 10_000,
    include: ['packages/**/*.test.ts', 'test/**/*.test.ts'],
    testTimeout: 10_000,
  },
});

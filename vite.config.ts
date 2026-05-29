import { defineConfig } from 'vite';
import { readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf-8'));

export default defineConfig({
  resolve: {
    alias: {
      buffer: 'buffer/',
    },
  },
  define: {
    // Some libraries might expect 'global' to be available
    global: 'globalThis',
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
});

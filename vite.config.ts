import { defineConfig } from 'vite';

export default defineConfig({
  resolve: {
    alias: {
      buffer: 'buffer/',
    },
  },
  define: {
    // Some libraries might expect 'global' to be available
    global: 'globalThis',
  },
});

// ============================================================================
// Entry — installs the electronAPI adapter before the inline <script> in
// index.html accesses window.electronAPI. As a type="module" script this is
// implicitly deferred, so it runs after the parser sees the inline script
// (which only registers handlers) but before any user interaction or
// DOMContentLoaded callbacks fire.
// ============================================================================

import { Buffer } from 'buffer';
(window as unknown as Record<string, unknown>).Buffer = Buffer;

import { installElectronAPI } from './electronAPI-adapter.ts';

installElectronAPI();

// Injected by Vite from package.json (see vite.config.ts)
declare const __APP_VERSION__: string;

document.addEventListener('DOMContentLoaded', () => {
  const el = document.getElementById('app-version');
  if (el) el.textContent = `v${__APP_VERSION__}`;
});

const STORAGE_KEY = 'cipher-studio-settings';

export function loadSettings(): Record<string, unknown> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) return JSON.parse(raw) as Record<string, unknown>;
  } catch { /* ignore corrupt data */ }
  return {};
}

export function saveSettings(settings: Record<string, unknown>): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
}

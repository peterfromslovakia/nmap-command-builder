// Nastavenia automatickej kontroly aktualizacii (lokalne).
const STORE_KEY = 'ncb.updates.v1';
export const CHECK_INTERVAL_MS = 12 * 60 * 60 * 1000;

function defaultStorage() {
  try { return window.localStorage; } catch (_) { return null; }
}

export function loadUpdatePrefs(storage = defaultStorage()) {
  try {
    const p = JSON.parse(storage.getItem(STORE_KEY) || '{}') || {};
    return {
      auto: p.auto !== false,
      lastCheck: Number.isFinite(p.lastCheck) ? p.lastCheck : 0,
      dismissed: typeof p.dismissed === 'string' ? p.dismissed : '',
    };
  } catch (_) {
    return { auto: true, lastCheck: 0, dismissed: '' };
  }
}

export function saveUpdatePrefs(prefs, storage = defaultStorage()) {
  try { storage.setItem(STORE_KEY, JSON.stringify(prefs)); } catch (_) { /* ignore */ }
  return prefs;
}

/** Kontrolovat pri spusteni? Len ak je zapnuta a od poslednej presli aspon 12 h. */
export function shouldAutoCheck(prefs, now = Date.now()) {
  return prefs.auto && (now - prefs.lastCheck >= CHECK_INTERVAL_MS || prefs.lastCheck > now);
}

/** Zobrazit pruh? Len pre novu verziu, ktoru pouzivatel neodlozil. */
export function shouldShowBanner(result, prefs) {
  return Boolean(result && result.ok && result.available && result.latest !== prefs.dismissed);
}

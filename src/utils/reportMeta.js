import { normalizeMeta } from './report';

// Posledne pouzite udaje o teste (jazyk, kto test vykonal, ...) — len lokalne.
const STORE_KEY = 'ncb.reportMeta.v1';

function defaultStorage() {
  try { return window.localStorage; } catch (_) { return null; }
}

export function loadReportMeta(storage = defaultStorage()) {
  try {
    const raw = JSON.parse(storage.getItem(STORE_KEY) || 'null');
    return { ...normalizeMeta(raw && typeof raw === 'object' ? raw : {}), remember: raw ? raw.remember !== false : true, saved: Boolean(raw) };
  } catch (_) {
    return { ...normalizeMeta({}), remember: true, saved: false };
  }
}

/** Ulozi udaje; ak pouzivatel nechce, ulozi len jazyk (osobne udaje zmaze). */
export function saveReportMeta(meta, storage = defaultStorage()) {
  const m = normalizeMeta(meta);
  const data = meta.remember === false ? { lang: m.lang, remember: false } : { ...m, remember: true };
  try { storage.setItem(STORE_KEY, JSON.stringify(data)); } catch (_) { /* ignore */ }
  return data;
}

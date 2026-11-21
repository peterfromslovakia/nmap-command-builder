import { FLAG_MAP } from '../data/flags';
import { rootRequirements } from './privileges';

// ─── Vlastne presety pouzivatela ──────────────────────────────────────────────
// Ulozene len lokalne v aplikacii (localStorage). Pri nacitani sa data cistia:
// neznamy flag sa zahodi a hodnoty musia byt bool alebo kratky retazec —
// samotny prikaz este pred spustenim kontroluje whitelist v main procese.

const STORE_KEY = 'ncb.userPresets.v1';
export const MAX_USER_PRESETS = 50;
export const MAX_NAME = 60;
const MAX_VALUE = 500;

function defaultStorage() {
  try { return window.localStorage; } catch (_) { return null; }
}

/** Ponecha len zname flagy s platnymi hodnotami. */
export function sanitizeFlags(flags) {
  const out = {};
  if (!flags || typeof flags !== 'object') return out;
  for (const [id, v] of Object.entries(flags)) {
    if (!Object.prototype.hasOwnProperty.call(FLAG_MAP, id)) continue;
    if (v === true) out[id] = true;
    else if (typeof v === 'string' && v.trim() !== '' && v.length <= MAX_VALUE && !/[\0\r\n]/.test(v)) out[id] = v;
  }
  return out;
}

function sanitize(p) {
  if (!p || typeof p !== 'object') return null;
  const name = String(p.name || '').trim().slice(0, MAX_NAME);
  const flags = sanitizeFlags(p.flags);
  if (!name || Object.keys(flags).length === 0) return null;
  const target = typeof p.target === 'string' ? p.target.trim().slice(0, 200) : '';
  return {
    id: String(p.id || ''),
    name,
    flags,
    target,
    created: String(p.created || ''),
    requiresRoot: rootRequirements(flags).length > 0,
  };
}

export function loadUserPresets(storage = defaultStorage()) {
  try {
    const data = JSON.parse(storage.getItem(STORE_KEY) || '[]');
    return Array.isArray(data) ? data.map(sanitize).filter(Boolean) : [];
  } catch (_) {
    return [];
  }
}

function persist(list, storage) {
  try { storage.setItem(STORE_KEY, JSON.stringify(list)); } catch (_) { /* plne / zakazane ulozisko */ }
  return list;
}

/**
 * Ulozi preset; rovnaky nazov (bez ohladu na velkost pismen) prepise.
 * @returns {{ ok: boolean, error?: string, list: Array }}
 */
export function saveUserPreset({ name, flags, target = '' }, storage = defaultStorage(), now = new Date()) {
  const list = loadUserPresets(storage);
  const preset = sanitize({ id: `u${now.getTime()}`, name, flags, target, created: now.toISOString() });
  if (!preset) {
    return { ok: false, error: String(name || '').trim() ? 'Select at least one flag first' : 'Enter a name', list };
  }
  const rest = list.filter((p) => p.name.toLowerCase() !== preset.name.toLowerCase());
  if (rest.length >= MAX_USER_PRESETS) return { ok: false, error: `Limit is ${MAX_USER_PRESETS} presets`, list };
  return { ok: true, list: persist([preset, ...rest], storage) };
}

export function deleteUserPreset(id, storage = defaultStorage()) {
  return persist(loadUserPresets(storage).filter((p) => p.id !== id), storage);
}

// ─── Export / import (zdielanie predvolieb s kolegami) ───────────────────────
const EXPORT_TYPE = 'nmap-command-builder/presets';

/** JSON so zvolenymi predvolbami (bez ID a casov). */
export function exportUserPresets(list, withTargets = true) {
  return JSON.stringify({
    type: EXPORT_TYPE,
    version: 1,
    presets: list.map((p) => ({ name: p.name, flags: p.flags, ...(withTargets && p.target ? { target: p.target } : {}) })),
  }, null, 2);
}

/**
 * Nacita predvolby zo suboru. Kazda prejde rovnakym cistenim ako pri ulozeni
 * (nezname flagy sa zahodia); rovnaky nazov prepise existujucu predvolbu.
 * @returns {{ ok: boolean, error?: string, added: number, replaced: number, skipped: number, list: Array }}
 */
export function importUserPresets(text, storage = defaultStorage(), now = new Date()) {
  const current = loadUserPresets(storage);
  let data;
  try { data = JSON.parse(text); } catch (_) { return { ok: false, error: 'Not a valid presets file', added: 0, replaced: 0, skipped: 0, list: current }; }
  const items = data && data.type === EXPORT_TYPE && Array.isArray(data.presets) ? data.presets : null;
  if (!items) return { ok: false, error: 'Not a valid presets file', added: 0, replaced: 0, skipped: 0, list: current };

  let list = current;
  let added = 0; let replaced = 0; let skipped = 0;
  items.slice(0, MAX_USER_PRESETS * 2).forEach((raw, i) => {
    const p = sanitize({ ...raw, id: `u${now.getTime()}-${i}`, created: now.toISOString() });
    if (!p) { skipped += 1; return; }
    const exists = list.some((x) => x.name.toLowerCase() === p.name.toLowerCase());
    const rest = list.filter((x) => x.name.toLowerCase() !== p.name.toLowerCase());
    if (rest.length >= MAX_USER_PRESETS) { skipped += 1; return; }
    list = [p, ...rest];
    if (exists) replaced += 1; else added += 1;
  });
  return { ok: true, added, replaced, skipped, list: persist(list, storage) };
}

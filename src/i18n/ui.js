// ─── Jazyk rozhrania aplikacie (EN / SK) ─────────────────────────────────────
// t('English text', { var }) → preklad podla zvoleneho jazyka; {var} sa nahradi.
// Kluc = presny anglicky text; chybajuci preklad ostane po anglicky (test ho zachyti).
import React, { createContext, useContext, useMemo, useState, useCallback } from 'react';
import UI_SK from './uiSk';
import DATA_SK from './dataSk';

export const UI_LANGS = ['en', 'sk'];
const STORE_KEY = 'ncb.lang.v1';
const DICT = { sk: { ...DATA_SK, ...UI_SK } };

export function translate(lang, text, vars) {
  if (text == null) return '';
  const base = (DICT[lang] && Object.prototype.hasOwnProperty.call(DICT[lang], text)) ? DICT[lang][text] : text;
  return vars ? base.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m)) : base;
}

export function detectLang(nav = typeof navigator !== 'undefined' ? navigator : null) {
  const l = String((nav && (nav.language || (nav.languages || [])[0])) || '').toLowerCase();
  return /^(sk|cs)\b/.test(l) ? 'sk' : 'en';
}

export function loadLang(storage = typeof window !== 'undefined' ? window.localStorage : null) {
  try {
    const v = storage && storage.getItem(STORE_KEY);
    if (UI_LANGS.includes(v)) return v;
  } catch (_) { /* ignore */ }
  return detectLang();
}

export function saveLang(lang, storage = typeof window !== 'undefined' ? window.localStorage : null) {
  try { if (storage && UI_LANGS.includes(lang)) storage.setItem(STORE_KEY, lang); } catch (_) { /* ignore */ }
}

const LangContext = createContext({ lang: 'en', setLang: () => {}, t: (s, v) => translate('en', s, v) });

export function LangProvider({ children, initial }) {
  const [lang, setLangState] = useState(() => initial || loadLang());
  const setLang = useCallback((l) => { if (UI_LANGS.includes(l)) { setLangState(l); saveLang(l); } }, []);
  const value = useMemo(() => ({ lang, setLang, t: (s, v) => translate(lang, s, v) }), [lang, setLang]);
  return React.createElement(LangContext.Provider, { value }, children);
}

export const useLang = () => useContext(LangContext);
export const useT = () => useContext(LangContext).t;

// ─── Klavesove skratky ────────────────────────────────────────────────────────
// Mod = ⌘ na macOS, Ctrl inde. Zastavenie skenu je ⌘. / Ctrl+. (nie Esc),
// aby sa sken nedal ukoncit omylom pri zatvarani menu alebo vyhladavania.

export const TAB_ORDER = ['builder', 'cheatsheet', 'presets', 'scripts', 'ethics'];

/**
 * @param {{ key: string, metaKey?: boolean, ctrlKey?: boolean, shiftKey?: boolean, altKey?: boolean }} e
 * @param {boolean} isMac
 * @returns {null | { action: 'run'|'kill'|'search'|'copy'|'tab', tab?: string }}
 */
export function matchShortcut(e, isMac) {
  const mod = isMac ? e.metaKey && !e.ctrlKey : e.ctrlKey && !e.metaKey;
  if (!mod || e.altKey) return null;
  const key = String(e.key || '').toLowerCase();

  if (!e.shiftKey) {
    if (key === 'enter') return { action: 'run' };
    if (key === '.') return { action: 'kill' };
    if (key === 'f') return { action: 'search' };
    const n = Number(key);
    if (Number.isInteger(n) && n >= 1 && n <= TAB_ORDER.length) return { action: 'tab', tab: TAB_ORDER[n - 1] };
  } else if (key === 'c') {
    return { action: 'copy' };
  }
  return null;
}

/** Popis skratiek pre UI. */
export function shortcutHints(isMac) {
  const m = isMac ? '⌘' : 'Ctrl+';
  return [
    { keys: `${m}↵`, label: 'run scan' },
    { keys: `${m}.`, label: 'stop scan' },
    { keys: `${m}F`, label: 'search flags' },
    { keys: `${m}⇧C`.replace('Ctrl+⇧', 'Ctrl+Shift+'), label: 'copy command' },
    { keys: `${m}1–${TAB_ORDER.length}`, label: 'switch tab' },
  ];
}

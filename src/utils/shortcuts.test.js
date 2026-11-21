import { matchShortcut, shortcutHints, TAB_ORDER } from './shortcuts';

const mac = (key, extra = {}) => matchShortcut({ key, metaKey: true, ...extra }, true);
const win = (key, extra = {}) => matchShortcut({ key, ctrlKey: true, ...extra }, false);

test('macOS uses ⌘, other platforms Ctrl', () => {
  expect(mac('Enter')).toEqual({ action: 'run' });
  expect(win('Enter')).toEqual({ action: 'run' });
  expect(matchShortcut({ key: 'Enter', ctrlKey: true }, true)).toBeNull();
  expect(matchShortcut({ key: 'Enter', metaKey: true }, false)).toBeNull();
});

test('all actions', () => {
  expect(mac('.')).toEqual({ action: 'kill' });
  expect(mac('f')).toEqual({ action: 'search' });
  expect(mac('F')).toEqual({ action: 'search' });
  expect(mac('C', { shiftKey: true })).toEqual({ action: 'copy' });
  expect(win('3')).toEqual({ action: 'tab', tab: 'presets' });
  expect(win(String(TAB_ORDER.length))).toEqual({ action: 'tab', tab: 'ethics' });
});

test('plain keys, Escape, Alt combos and normal copy/paste are not captured', () => {
  ['Enter', 'Escape', 'f', '.', '1'].forEach((k) => expect(matchShortcut({ key: k }, true)).toBeNull());
  expect(mac('Escape')).toBeNull();
  expect(mac('c')).toBeNull();
  expect(mac('v')).toBeNull();
  expect(mac('a')).toBeNull();
  expect(mac('Enter', { altKey: true })).toBeNull();
  expect(win('0')).toBeNull();
  expect(win('9')).toBeNull();
});

test('hints are platform-specific', () => {
  expect(shortcutHints(true)[0].keys).toBe('⌘↵');
  expect(shortcutHints(false).map((h) => h.keys)).toContain('Ctrl+Shift+C');
});

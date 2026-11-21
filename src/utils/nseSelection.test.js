import { parseList, toggleScript, removeScripts, addScriptArg } from './nseSelection';
import { NSE_SCRIPTS, NSE_CATEGORIES, scriptRisk } from '../data/nseScripts';

describe('nseSelection', () => {
  test('parseList trims and drops empty items', () => {
    expect(parseList(' vuln, ,banner ,')).toEqual(['vuln', 'banner']);
    expect(parseList(undefined)).toEqual([]);
  });

  test('toggleScript adds and removes', () => {
    expect(toggleScript('', 'banner')).toBe('banner');
    expect(toggleScript('banner', 'ssl-cert')).toBe('banner,ssl-cert');
    expect(toggleScript('banner,ssl-cert', 'banner')).toBe('ssl-cert');
  });

  test('toggleScript keeps boolean expressions intact', () => {
    expect(toggleScript('default and safe', 'banner')).toBe('default and safe,banner');
  });

  test('removeScripts drops listed names', () => {
    expect(removeScripts('a,b,c', ['b', 'x'])).toBe('a,c');
  });

  test('addScriptArg does not duplicate keys', () => {
    expect(addScriptArg('', 'mincvss', '7.0')).toBe('mincvss=7.0');
    expect(addScriptArg('mincvss=5', 'mincvss', '7.0')).toBe('mincvss=5');
    expect(addScriptArg('a=1', 'ssh.user', 'root')).toBe('a=1,ssh.user=root');
  });
});

describe('nseScripts data', () => {
  const MAIN_SCRIPT_RE = /^[A-Za-z0-9_,*.+() -]+$/; // zhodne s electron/main.js
  const catIds = new Set(NSE_CATEGORIES.map((c) => c.id));

  test('names are unique and accepted by the main-process validator', () => {
    const names = NSE_SCRIPTS.map((x) => x.name);
    expect(new Set(names).size).toBe(names.length);
    names.forEach((n) => expect(MAIN_SCRIPT_RE.test(n)).toBe(true));
  });

  test('every script uses known categories', () => {
    NSE_SCRIPTS.forEach((x) => x.categories.forEach((c) => expect(catIds.has(c)).toBe(true)));
  });

  test('scriptRisk', () => {
    expect(scriptRisk(['default', 'safe'])).toBe('safe');
    expect(scriptRisk(['discovery', 'intrusive'])).toBe('intrusive');
    expect(scriptRisk(['intrusive', 'brute'])).toBe('dangerous');
  });
});

import fs from 'fs';
import path from 'path';
import UI_SK from './uiSk';
import DATA_SK from './dataSk';
import { translate, detectLang, loadLang, saveLang } from './ui';
import { FLAG_CATEGORIES } from '../data/flags';
import { PRESETS } from '../data/presets';
import { NSE_CATEGORIES, NSE_SCRIPTS } from '../data/nseScripts';
import { CHEATSHEET } from '../data/cheatsheet';
import { getPortIntel } from '../data/portIntel';
import { DEVICE_TYPES } from '../utils/inventory';
import { shortcutHints } from '../utils/shortcuts';
import { rootRequirements, ROOT_FLAG_IDS } from '../utils/privileges';

const has = (dict, k) => Object.prototype.hasOwnProperty.call(dict, k);
const ALL = { ...DATA_SK, ...UI_SK };

/** Texty z dat, ktore UI zobrazuje cez t(). */
export function dataStrings() {
  const s = new Set();
  FLAG_CATEGORIES.forEach((c) => {
    s.add(c.name);
    c.flags.forEach((f) => {
      ['name', 'description', 'warning'].forEach((k) => f[k] && s.add(f[k]));
      (f.options || []).forEach((o) => s.add(o.label));
    });
  });
  PRESETS.forEach((p) => ['name', 'description', 'warning', 'riskNote'].forEach((k) => p[k] && s.add(p[k])));
  NSE_CATEGORIES.forEach((c) => s.add(c.description));
  NSE_SCRIPTS.forEach((x) => { s.add(x.description); x.args.forEach((a) => s.add(a.description)); });
  CHEATSHEET.forEach((c) => { s.add(c.category); c.items.forEach((i) => s.add(i.description)); });
  for (let p = 1; p < 65536; p++) {
    const i = getPortIntel(p);
    if (i) { i.hints.forEach((h) => s.add(h)); i.followUp.forEach((f) => s.add(f.label)); }
  }
  return s;
}

/** Texty pouzite v komponentoch: t('…') + dynamicke kluce (typy zariadeni, skratky, tipy…). */
export function uiStrings() {
  const s = new Set();
  const dir = path.join(__dirname, '..');
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).forEach((e) => {
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p);
    else if (/\.(jsx?|tsx?)$/.test(e.name) && !/\.test\./.test(e.name)) {
      const src = fs.readFileSync(p, 'utf8');
      for (const m of src.matchAll(/\b[tT](?:Ref\.current)?\(\s*(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")/g)) {
        s.add((m[1] ?? m[2]).replace(/\\'/g, "'").replace(/\\"/g, '"'));
      }
    }
  });
  walk(path.join(dir, 'components'));
  ['App.js'].forEach((f) => {
    const src = fs.readFileSync(path.join(dir, f), 'utf8');
    for (const m of src.matchAll(/\b[tT](?:Ref\.current)?\(\s*(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")/g)) s.add((m[1] ?? m[2]).replace(/\\'/g, "'"));
  });
  Object.values(DEVICE_TYPES).forEach((d) => s.add(d.label));
  shortcutHints(true).forEach((h) => s.add(h.label));
  ROOT_FLAG_IDS.forEach((id) => rootRequirements({ [id]: true }).forEach((r) => r.tip && s.add(r.tip)));
  // validator / vlastne predvolby / typy v mape siete / urovne rizika
  ['Target is required', 'Target contains invalid characters', 'Not a valid presets file', 'File is too large.', 'No report folder chosen.', 'Invalid or too large report.', 'unknown error', 'Select at least one flag first', 'Enter a name',
    'critical vulnerability', 'high-risk vulnerability', 'medium vulnerability', 'low vulnerability', 'risky open ports', 'nothing found',
    'NEW VULNERABILITIES', 'NEW OPEN PORTS', 'NEW HOSTS', 'VERSION CHANGES', 'FIXED VULNERABILITIES', 'CLOSED PORTS', 'FILTERED PORTS', 'NOT TESTED PORTS', 'HOSTS NOT FOUND',
    'CRIT', 'CRITICAL', 'HIGH', 'MEDIUM', 'MED', 'LOW', 'SAFE', 'INTRUSIVE', 'ADV', 'INFO', 'NOISY',
    'Standard scan', 'Likely to be logged / detected by IDS', 'May disrupt services or lock accounts — written permission required',
    'Performed by', 'Organisation', 'Client / system owner', 'Authorisation ref.',
    'Name of the person who ran the test', 'Company / team (optional)', 'Whose systems were tested (optional)', 'Contract / order / ticket number (optional)',
  ].forEach((x) => s.add(x));
  return s;
}

test('every UI text and data text has a Slovak translation', () => {
  const missing = [...new Set([...uiStrings(), ...dataStrings()])].filter((k) => !has(ALL, k)).sort();
  expect(missing).toEqual([]);
});

test('no unused translations', () => {
  const used = new Set([...uiStrings(), ...dataStrings()]);
  expect(Object.keys(UI_SK).filter((k) => !used.has(k))).toEqual([]);
  expect(Object.keys(DATA_SK).filter((k) => !used.has(k))).toEqual([]);
});

test('placeholders and technical tokens survive translation', () => {
  Object.entries(ALL).forEach(([en, sk]) => {
    const vars = (x) => (x.match(/\{\w+\}/g) || []).sort();
    expect([en, vars(sk)]).toEqual([en, vars(en)]);
    [...en.matchAll(/(?:^|[\s(/,])(-{1,2}[a-zA-Z][\w-]*)|(CVE-\d{4}-\d+|MS\d{2}-\d{3}|\d{2,5})/g)].map((m) => m[1] || m[2]).forEach((tok) => {
      expect([en, sk.includes(tok)]).toEqual([en, true]);
    });
  });
});

test('translate: lookup, fallback, variables', () => {
  expect(translate('sk', 'RUN SCAN')).toBe(UI_SK['RUN SCAN']);
  expect(translate('en', 'RUN SCAN')).toBe('RUN SCAN');
  expect(translate('sk', 'unknown text')).toBe('unknown text');
  expect(translate('en', 'Version {v}', { v: '1.5.0' })).toBe('Version 1.5.0');
  expect(translate('sk', 'Version {v}', { v: '1.5.0' })).toContain('1.5.0');
});

test('language detection and storage', () => {
  expect(detectLang({ language: 'sk-SK' })).toBe('sk');
  expect(detectLang({ language: 'cs' })).toBe('sk');
  expect(detectLang({ language: 'en-US' })).toBe('en');
  const m = {};
  const st = { getItem: (k) => m[k] ?? null, setItem: (k, v) => { m[k] = v; } };
  saveLang('sk', st);
  expect(loadLang(st)).toBe('sk');
  saveLang('de', st);
  expect(loadLang(st)).toBe('sk');
  expect(loadLang({ getItem: () => { throw new Error('x'); } })).toMatch(/^(en|sk)$/);
});

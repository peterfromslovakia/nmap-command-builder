const test = require('node:test');
const assert = require('node:assert');
const { buildMenuTemplate, LINKS } = require('./menu');

const flat = (items) => items.flatMap((i) => [i, ...(Array.isArray(i.submenu) ? flat(i.submenu) : [])]);
const make = (o) => {
  const opened = [];
  const tpl = buildMenuTemplate({ isMac: true, isDev: false, appName: 'Nmap Command Builder', openUrl: (u) => opened.push(u), showAbout: () => opened.push('about'), checkUpdates: () => opened.push('check'), ...o });
  return { tpl, items: flat(tpl), opened };
};

test('Edit menu is present (copy / paste in inputs on macOS)', () => {
  assert.ok(make().items.some((i) => i.role === 'editMenu'));
  assert.ok(make({ isMac: false }).items.some((i) => i.role === 'editMenu'));
});

test('no DevTools or reload in production, available in development', () => {
  const roles = (o) => make(o).items.map((i) => i.role);
  assert.ok(!roles({ isDev: false }).includes('toggleDevTools'));
  assert.ok(!roles({ isDev: false }).includes('reload'));
  assert.ok(roles({ isDev: true }).includes('toggleDevTools'));
});

test('help links open only fixed https URLs on nmap.org / the project repo', () => {
  const { items, opened } = make();
  items.filter((i) => i.click).forEach((i) => i.click());
  assert.ok(opened.includes('check'));
  const urls = opened.filter((u) => u !== 'check');
  assert.strictEqual(urls.length, Object.keys(LINKS).length);
  urls.forEach((u) => assert.match(u, /^https:\/\/(nmap\.org|github\.com\/peterfromslovakia\/nmap-command-builder)(\/|$)/));
});

test('About: app menu on macOS, Help menu elsewhere', () => {
  assert.ok(make().items.some((i) => i.role === 'about'));
  const { items, opened } = make({ isMac: false });
  items.find((i) => /^About/.test(i.label || '')).click();
  assert.deepStrictEqual(opened, ['about']);
});

test('no menu accelerators clash with the in-app shortcuts', () => {
  const accels = make().items.map((i) => i.accelerator).filter(Boolean);
  ['CmdOrCtrl+Enter', 'CmdOrCtrl+.', 'CmdOrCtrl+F', 'CmdOrCtrl+Shift+C'].forEach((a) => assert.ok(!accels.includes(a)));
});

test('menu labels follow the UI language (en / sk), unknown falls back to English', () => {
  const { menuText } = require('./menu');
  const labels = (lang) => JSON.stringify(make({ isMac: false, lang }).tpl.map((m) => [m.label, (m.submenu || []).map((x) => x.label)]));
  assert.match(labels('sk'), /Súbor.*Zobrazenie/);
  assert.match(labels('sk'), /Skontrolovať aktualizácie…/);
  assert.strictEqual(labels('de'), labels('en'));
  assert.deepStrictEqual(Object.keys(menuText('sk')).sort(), Object.keys(menuText('en')).sort());
});

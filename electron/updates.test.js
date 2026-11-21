const test = require('node:test');
const assert = require('node:assert');
const { compareVersions, pickAsset, isDownloadUrl, checkForUpdate, API_URL } = require('./updates');

const DL = 'https://github.com/peterfromslovakia/nmap-command-builder/releases/download/v1.4.0/';
const ASSETS = [
  { name: 'Nmap-Command-Builder-1.4.0-arm64.dmg', browser_download_url: `${DL}Nmap-Command-Builder-1.4.0-arm64.dmg`, size: 1 },
  { name: 'Nmap-Command-Builder-1.4.0-x64.dmg', browser_download_url: `${DL}Nmap-Command-Builder-1.4.0-x64.dmg`, size: 2 },
  { name: 'Nmap-Command-Builder-Setup-1.4.0.exe', browser_download_url: `${DL}Nmap-Command-Builder-Setup-1.4.0.exe`, size: 3 },
  { name: 'Nmap-Command-Builder-1.4.0.AppImage', browser_download_url: `${DL}Nmap-Command-Builder-1.4.0.AppImage`, size: 4 },
];

test('compareVersions', () => {
  assert.strictEqual(compareVersions('v1.10.0', '1.9.2'), 1);
  assert.strictEqual(compareVersions('1.3.0', 'v1.3.0'), 0);
  assert.strictEqual(compareVersions('1.2.9', '1.3.0'), -1);
  assert.strictEqual(compareVersions('garbage', '0.0.1'), -1);
});

test('picks the right installer for each platform and Mac CPU', () => {
  assert.strictEqual(pickAsset(ASSETS, 'darwin', 'arm64').name, 'Nmap-Command-Builder-1.4.0-arm64.dmg');
  assert.strictEqual(pickAsset(ASSETS, 'darwin', 'x64').name, 'Nmap-Command-Builder-1.4.0-x64.dmg');
  assert.strictEqual(pickAsset(ASSETS, 'win32', 'x64').name, 'Nmap-Command-Builder-Setup-1.4.0.exe');
  assert.strictEqual(pickAsset(ASSETS, 'linux', 'x64').name, 'Nmap-Command-Builder-1.4.0.AppImage');
  assert.strictEqual(pickAsset(ASSETS, 'freebsd', 'x64'), null);
  assert.strictEqual(pickAsset(null, 'linux', 'x64'), null);
});

test('download links must point to this repository releases', () => {
  assert.ok(isDownloadUrl(`${DL}x.dmg`));
  assert.ok(!isDownloadUrl('https://evil.example/releases/x.dmg'));
  assert.ok(!isDownloadUrl('https://github.com/someone-else/nmap-command-builder/releases/x.dmg'));
  assert.ok(!isDownloadUrl(`${DL}x.dmg" onclick="x`));
  const bad = [{ name: 'Nmap-Command-Builder-1.4.0.AppImage', browser_download_url: 'https://evil.example/a.AppImage' }];
  assert.strictEqual(pickAsset(bad, 'linux', 'x64'), null);
});

const fakeFetch = (body, status = 200) => async (url, opts) => {
  assert.strictEqual(url, API_URL);
  assert.ok(opts.headers['User-Agent']);
  return { ok: status === 200, status, json: async () => body };
};

test('newer release → available with the platform installer', async () => {
  const r = await checkForUpdate('1.3.0', {
    fetchFn: fakeFetch({ tag_name: 'v1.4.0', html_url: `${DL.replace('download/v1.4.0/', 'tag/v1.4.0')}`, assets: ASSETS }),
    platform: 'darwin', arch: 'x64',
  });
  assert.strictEqual(r.available, true);
  assert.strictEqual(r.latest, '1.4.0');
  assert.strictEqual(r.asset.name, 'Nmap-Command-Builder-1.4.0-x64.dmg');
});

test('same or older version, drafts and prereleases → not available', async () => {
  for (const body of [{ tag_name: 'v1.3.0' }, { tag_name: 'v1.2.0' }, { tag_name: 'v9.0.0', prerelease: true }, { tag_name: 'v9.0.0', draft: true }]) {
    const r = await checkForUpdate('1.3.0', { fetchFn: fakeFetch(body), platform: 'linux' });
    assert.strictEqual(r.available, false, JSON.stringify(body));
  }
});

test('network problems are reported, never thrown', async () => {
  assert.strictEqual((await checkForUpdate('1.3.0', { fetchFn: fakeFetch({}, 403) })).ok, false);
  const r = await checkForUpdate('1.3.0', { fetchFn: async () => { throw new Error('offline'); } });
  assert.deepStrictEqual(r, { ok: false, error: 'offline' });
  const slow = await checkForUpdate('1.3.0', {
    timeoutMs: 20,
    fetchFn: (_u, o) => new Promise((_, rej) => o.signal.addEventListener('abort', () => rej(Object.assign(new Error('x'), { name: 'AbortError' })))),
  });
  assert.deepStrictEqual(slow, { ok: false, error: 'Timed out' });
});

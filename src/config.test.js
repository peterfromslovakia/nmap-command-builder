// Regresne testy konfiguracie — strazia chyby, ktore sa uz raz stali.
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
const pkg = JSON.parse(read('package.json'));

describe('layout', () => {
  test('no 100vh/100vw heights in CSS (UI zoom would push the footer off-screen)', () => {
    ['src/App.css'].forEach((f) => expect(read(f)).not.toMatch(/100v[hw]/));
  });

  test('#root size compensates the adaptive UI zoom', () => {
    const css = read('src/index.css');
    expect(css).toMatch(/zoom:\s*var\(--ui-zoom\)/);
    expect(css).toContain('height: calc(100vh / var(--ui-zoom))');
  });
});

describe('release', () => {
  test('CHANGELOG has a section for the current version', () => {
    expect(read('CHANGELOG.md')).toMatch(new RegExp(`^## ${pkg.version.replace(/\./g, '\\.')}\\b`, 'm'));
  });

  test('electron-builder does not publish on its own (duplicate release assets)', () => {
    expect(read('.github/workflows/release.yml')).toContain('npm run dist -- --publish never');
  });

  test('macOS build is ad-hoc signed (otherwise macOS reports the app as damaged)', () => {
    expect(pkg.build.afterPack).toBe('scripts/adhoc-sign.js');
    expect(fs.existsSync(path.join(root, pkg.build.afterPack))).toBe(true);
  });

  test('test files are not packaged into the app', () => {
    expect(pkg.build.files).toContain('!electron/**/*.test.js');
  });

  test('LICENSE file matches the license in package.json', () => {
    expect(pkg.license).toBe('MIT');
    expect(read('LICENSE')).toMatch(/^MIT License/);
  });

  test('macOS builds for both Apple Silicon and Intel', () => {
    const t = pkg.build.mac.target.find((x) => x.target === 'dmg');
    expect([...t.arch].sort()).toEqual(['arm64', 'x64']);
  });

  test('installer names match what the update check looks for', () => {
    // electron/updates.js pickAsset(): -<arch>.dmg, Setup-*.exe, *.AppImage
    // eslint-disable-next-line no-template-curly-in-string -- zastupne symboly electron-builderu
    const name = (tpl, arch) => tpl.replace('${version}', '9.9.9').replace('${arch}', arch).replace('${ext}', '');
    expect(name(pkg.build.mac.artifactName, 'arm64')).toMatch(/-arm64\.$/);
    expect(name(pkg.build.mac.artifactName, 'x64')).toMatch(/-x64\.$/);
    expect(name(pkg.build.nsis.artifactName)).toMatch(/Setup-.*\.$/);
    expect(pkg.build.linux.artifactName).toMatch(/\.\$\{ext\}$/);
    expect(pkg.build.linux.target).toBe('AppImage');
  });

  test('artifact names contain no spaces', () => {
    ['mac', 'nsis', 'linux'].forEach((k) => expect(pkg.build[k].artifactName).not.toMatch(/\s|\$\{productName\}/));
  });
});

describe('version', () => {
  test('footer version matches package.json', () => {
    expect(read('src/App.js')).toContain(`Nmap Command Builder v${pkg.version}<`);
  });

  test('CHANGELOG has a section for the current version (used as release notes)', () => {
    expect(read('CHANGELOG.md')).toMatch(new RegExp(`^## ${pkg.version.replace(/\./g, '\\.')} — \\d{4}-\\d{2}-\\d{2}$`, 'm'));
  });
});

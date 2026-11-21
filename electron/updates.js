// ─── Kontrola novej verzie ────────────────────────────────────────────────────
// Jediny poziadavok: GET na verejne GitHub API (posledne vydanie). Neposiela
// ziadne udaje o skenoch ani o pouzivatelovi. Stiahnutie otvori prehliadac —
// aplikacia nic sama neinstaluje (na macOS by to bez Apple certifikatu neslo).

const REPO = 'peterfromslovakia/nmap-command-builder';
const API_URL = `https://api.github.com/repos/${REPO}/releases/latest`;
const DOWNLOAD_PREFIX = `https://github.com/${REPO}/releases/`;

/** "v1.10.0" > "1.9.2" — porovnanie po cislach; neplatna verzia = 0.0.0. */
function compareVersions(a, b) {
  const parse = (v) => {
    const m = String(v || '').trim().replace(/^v/i, '').match(/^(\d+)\.(\d+)\.(\d+)/);
    return m ? m.slice(1).map(Number) : [0, 0, 0];
  };
  const [x, y] = [parse(a), parse(b)];
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] > y[i] ? 1 : -1;
  return 0;
}

/** Instalacny subor pre danu platformu (nazvy podla artifactName v package.json). */
function pickAsset(assets, platform, arch) {
  const list = Array.isArray(assets) ? assets : [];
  const test = {
    darwin: (n) => n.endsWith(`-${arch === 'x64' ? 'x64' : 'arm64'}.dmg`),
    win32: (n) => /Setup-.*\.exe$/.test(n),
    linux: (n) => n.endsWith('.AppImage'),
  }[platform];
  const a = test && list.find((x) => x && typeof x.name === 'string' && test(x.name));
  return a && isDownloadUrl(a.browser_download_url) ? { name: a.name, url: a.browser_download_url, size: a.size } : null;
}

function isDownloadUrl(url) {
  return typeof url === 'string' && url.startsWith(DOWNLOAD_PREFIX) && !/[\s"'<>]/.test(url);
}

/**
 * @param {string} current  aktualna verzia (app.getVersion())
 * @param {(url, opts) => Promise<Response>} fetchFn  net.fetch / fetch
 */
async function checkForUpdate(current, { fetchFn, platform = process.platform, arch = process.arch, timeoutMs = 8000 }) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetchFn(API_URL, {
      headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'nmap-command-builder-update-check' },
      signal: ctrl.signal,
    });
    if (!res.ok) return { ok: false, error: `GitHub responded ${res.status}` };
    const rel = await res.json();
    if (!rel || rel.draft || rel.prerelease) return { ok: true, available: false, current };
    const latest = String(rel.tag_name || '').replace(/^v/i, '');
    const available = compareVersions(latest, current) > 0;
    return {
      ok: true,
      available,
      current,
      latest,
      pageUrl: isDownloadUrl(rel.html_url) ? rel.html_url : `${DOWNLOAD_PREFIX}latest`,
      asset: available ? pickAsset(rel.assets, platform, arch) : null,
    };
  } catch (err) {
    return { ok: false, error: err.name === 'AbortError' ? 'Timed out' : err.message };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { compareVersions, pickAsset, isDownloadUrl, checkForUpdate, API_URL, DOWNLOAD_PREFIX };

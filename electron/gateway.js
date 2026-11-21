// ─── Predvolena brana (router) — pre mapu siete ──────────────────────────────
// Bez root: macOS `route -n get default`, Linux /proc/net/route,
// Windows `route print -4 0.0.0.0`.

const fs = require('fs');
const { execFile } = require('child_process');

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const isIpv4 = (s) => {
  const m = IPV4.exec(String(s || ''));
  return Boolean(m) && m.slice(1).every((n) => Number(n) <= 255) && s !== '0.0.0.0';
};

/** macOS: "gateway: 192.168.1.1" */
function parseMacRoute(text) {
  const m = String(text || '').match(/^\s*gateway:\s*(\S+)/m);
  return m && isIpv4(m[1]) ? m[1] : null;
}

/** Linux /proc/net/route: brana je little-endian hex v riadku s Destination 00000000. */
function parseProcRoute(text) {
  for (const line of String(text || '').split('\n').slice(1)) {
    const c = line.trim().split(/\s+/);
    if (c.length < 3 || c[1] !== '00000000' || !/^[0-9A-F]{8}$/i.test(c[2])) continue;
    const ip = [6, 4, 2, 0].map((i) => parseInt(c[2].slice(i, i + 2), 16)).join('.');
    if (isIpv4(ip)) return ip;
  }
  return null;
}

/** Windows `route print`: "0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.15  25" (najnizsia metrika). */
function parseWinRoute(text) {
  let best = null;
  for (const line of String(text || '').split(/\r?\n/)) {
    const c = line.trim().split(/\s+/);
    if (c.length >= 5 && c[0] === '0.0.0.0' && c[1] === '0.0.0.0' && isIpv4(c[2])) {
      const metric = Number(c[4]);
      if (!best || metric < best.metric) best = { ip: c[2], metric };
    }
  }
  return best ? best.ip : null;
}

function defaultGateway(platform = process.platform) {
  return new Promise((resolve) => {
    if (platform === 'linux') {
      fs.readFile('/proc/net/route', 'utf8', (err, text) => resolve(err ? null : parseProcRoute(text)));
      return;
    }
    const [cmd, args, parse] = platform === 'win32'
      ? ['route', ['print', '-4', '0.0.0.0'], parseWinRoute]
      : ['route', ['-n', 'get', 'default'], parseMacRoute];
    execFile(cmd, args, { timeout: 5000, windowsHide: true, maxBuffer: 512 * 1024 }, (err, stdout) => {
      resolve(err ? null : parse(stdout));
    });
  });
}

module.exports = { defaultGateway, parseMacRoute, parseProcRoute, parseWinRoute };

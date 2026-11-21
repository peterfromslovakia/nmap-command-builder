// ─── MAC adresy a vyrobcovia zariadeni (bez root a bez internetu) ─────────────
// MAC adresy berieme z ARP tabulky systemu — po skene siete v nej su zariadenia,
// s ktorymi pocitac komunikoval. Vyrobcu urcime z databazy nmap-mac-prefixes,
// ktoru nmap instaluje spolu so sebou (zdroj: IEEE OUI register).

const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');

/** "c:ea:14:69:96:a8" / "0C-EA-14-69-96-A8" → "0C:EA:14:69:96:A8"; neplatna → null */
function normalizeMac(raw) {
  const parts = String(raw || '').trim().split(/[:-]/);
  if (parts.length !== 6 || !parts.every((p) => /^[0-9a-f]{1,2}$/i.test(p))) return null;
  const mac = parts.map((p) => p.padStart(2, '0').toUpperCase()).join(':');
  if (mac === 'FF:FF:FF:FF:FF:FF' || mac === '00:00:00:00:00:00') return null;
  if (parseInt(parts[0], 16) & 1) return null; // multicast
  return mac;
}

/** Nahodna (privatna) MAC — telefony a notebooky ju pouzivaju vo Wi-Fi; vyrobcu z nej nezistime. */
function isRandomizedMac(mac) {
  return Boolean(mac) && (parseInt(mac.slice(0, 2), 16) & 2) === 2;
}

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;

/** Vystup `arp -an` (macOS/Linux), `arp -a` (Windows) alebo /proc/net/arp → [{ ip, mac }] */
function parseArp(text) {
  const out = new Map();
  for (const line of String(text || '').split(/\r?\n/)) {
    let ip = null;
    let mac = null;
    let m = line.match(/\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9a-f:]+)/i); // macOS / Linux arp
    if (m) [, ip, mac] = m;
    if (!m) {
      m = line.match(/^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\s+\w+/i); // Windows
      if (m) [, ip, mac] = m;
    }
    if (!m) {
      m = line.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s+0x\w+\s+0x(\w+)\s+([0-9a-f:]{17})/i); // /proc/net/arp
      if (m && m[2] !== '0') { ip = m[1]; mac = m[3]; } else m = null;
    }
    const norm = normalizeMac(mac);
    if (ip && IPV4.test(ip) && norm && !out.has(ip)) out.set(ip, norm);
  }
  return [...out].map(([ip, m]) => ({ ip, mac: m }));
}

/** nmap-mac-prefixes → Map(prefix → vyrobca); predpony maju 6, 7 alebo 9 hex znakov. */
function parseOui(text) {
  const map = new Map();
  for (const line of String(text || '').split('\n')) {
    const m = line.match(/^([0-9A-F]{6,9})\s+(.+?)\s*$/i);
    if (m) map.set(m[1].toUpperCase(), m[2]);
  }
  return map;
}

function lookupVendor(mac, oui) {
  if (!mac || !oui) return null;
  if (isRandomizedMac(mac)) return null;
  const hex = mac.replace(/:/g, '');
  for (const len of [9, 7, 6]) {
    const v = oui.get(hex.slice(0, len));
    if (v) return v;
  }
  return null;
}

/** Kde moze byt nmap-mac-prefixes (podla platformy a umiestnenia nmapu v PATH). */
function ouiCandidates(env = process.env, platform = process.platform) {
  const list = [];
  for (const dir of String(env.PATH || '').split(path.delimiter)) {
    if (dir) list.push(path.join(dir, '..', 'share', 'nmap', 'nmap-mac-prefixes'), path.join(dir, 'nmap-mac-prefixes'));
  }
  if (platform === 'win32') {
    list.push('C:\\Program Files (x86)\\Nmap\\nmap-mac-prefixes', 'C:\\Program Files\\Nmap\\nmap-mac-prefixes');
  } else {
    list.push('/opt/homebrew/share/nmap/nmap-mac-prefixes', '/usr/local/share/nmap/nmap-mac-prefixes', '/usr/share/nmap/nmap-mac-prefixes');
  }
  return [...new Set(list)];
}

let ouiCache = null;
function loadOui() {
  if (ouiCache) return ouiCache;
  for (const file of ouiCandidates()) {
    try {
      ouiCache = parseOui(fs.readFileSync(file, 'utf8'));
      if (ouiCache.size > 0) return ouiCache;
    } catch (_) { /* skusit dalsi */ }
  }
  ouiCache = new Map();
  return ouiCache;
}

/** ARP tabulka systemu — pevny prikaz bez shellu; pri chybe prazdny zoznam. */
function readArpTable(platform = process.platform) {
  return new Promise((resolve) => {
    if (platform === 'linux') {
      try { resolve(parseArp(fs.readFileSync('/proc/net/arp', 'utf8'))); return; } catch (_) { /* fallback na arp */ }
    }
    const args = platform === 'win32' ? ['-a'] : ['-an'];
    execFile('arp', args, { timeout: 5000, windowsHide: true, maxBuffer: 2 * 1024 * 1024 }, (err, stdout) => {
      resolve(err && !stdout ? [] : parseArp(stdout));
    });
  });
}

/** [{ ip, mac, vendor, randomized }] pre zariadenia v ARP tabulke. */
async function arpDevices() {
  const oui = loadOui();
  return (await readArpTable()).map(({ ip, mac }) => ({
    ip, mac, vendor: lookupVendor(mac, oui), randomized: isRandomizedMac(mac),
  }));
}

module.exports = {
  normalizeMac, isRandomizedMac, parseArp, parseOui, lookupVendor, ouiCandidates, arpDevices,
};

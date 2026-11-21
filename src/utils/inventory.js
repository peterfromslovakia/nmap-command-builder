// ─── Inventar zariadeni v sieti ───────────────────────────────────────────────
// Z vystupu nmapu (+ ARP tabulky systemu) zostavi zoznam zariadeni so zakladnymi
// informaciami a odhadom typu zariadenia.

// Prehladanie siete jednym tlacidlom. TCP ping na typicke porty funguje aj bez
// root (connect); zachyti aj zariadenia, ktore neodpovedaju na port 80/443.
const PING_PORTS = '21,22,23,53,80,135,139,443,445,515,554,631,3389,5000,8000,8080,8443,9100,62078';

export const DISCOVERY_MODES = {
  quick: {
    flags: { ping_scan: true, ps: PING_PORTS, timing_template: '4' },
  },
  standard: {
    flags: { ps: PING_PORTS, fast: true, sv: true, version_light: true, timing_template: '4', host_timeout: '120s' },
  },
};

const RE_HOST = /^Nmap scan report for (\S+)(?:\s+\(([^)]+)\))?\s*$/;
const RE_UP = /^Host is up(?: \(([\d.]+)s latency\))?/;
const RE_MAC = /^MAC Address:\s+([0-9A-F:]{17})(?:\s+\((.*)\))?/i;
const RE_PORT = /^(\d+)\/(tcp|udp)\s+(open|open\|filtered)\s+(\S+)(?:\s+(.*))?$/;
const RE_SVCINFO = /^Service Info:\s*(.+)$/;
const RE_OS = /^(?:OS details|Running(?: \(JUST GUESSING\))?):\s*(.+)$/;

/** Zariadenia z textoveho vystupu nmapu. */
export function parseInventory(text) {
  const devices = [];
  let cur = null;
  for (const raw of String(text || '').split('\n')) {
    const line = raw.replace(/\r$/, '');
    let m = line.match(RE_HOST);
    if (m) {
      cur = {
        ip: m[2] || m[1],
        hostname: m[2] ? m[1] : '',
        latencyMs: null, mac: '', vendor: '', randomizedMac: false,
        ports: [], os: '', deviceHint: '',
      };
      devices.push(cur);
      continue;
    }
    if (!cur) continue;
    if ((m = line.match(RE_UP))) { if (m[1]) cur.latencyMs = Math.round(parseFloat(m[1]) * 10000) / 10; continue; }
    if ((m = line.match(RE_MAC))) { cur.mac = m[1].toUpperCase(); cur.vendor = m[2] && m[2] !== 'Unknown' ? m[2] : ''; continue; }
    if ((m = line.match(RE_PORT))) {
      cur.ports.push({ port: Number(m[1]), proto: m[2], service: m[4], version: (m[5] || '').trim() });
      continue;
    }
    if ((m = line.match(RE_SVCINFO))) {
      const os = m[1].match(/OSs?:\s*([^;]+)/);
      const dev = m[1].match(/Device:\s*([^;]+)/);
      if (os && !cur.os) cur.os = os[1].trim();
      if (dev) cur.deviceHint = dev[1].trim();
      continue;
    }
    if ((m = line.match(RE_OS))) cur.os = m[1].trim();
  }
  return devices;
}

/** Doplni MAC a vyrobcu z ARP tabulky (bez root nmap MAC nezisti). */
export function mergeArp(devices, arp = []) {
  const byIp = new Map(arp.map((a) => [a.ip, a]));
  return devices.map((d) => {
    const a = byIp.get(d.ip);
    if (!a || d.mac) return d;
    return { ...d, mac: a.mac, vendor: a.vendor || d.vendor, randomizedMac: Boolean(a.randomized) };
  });
}

// ─── Typ zariadenia ───────────────────────────────────────────────────────────
// Odhad podla otvorenych portov, vyrobcu sietovej karty, nazvu a "Service Info".
// Poradie pravidiel je dolezite — specifickejsie pravidla su skor.

export const DEVICE_TYPES = {
  router:   { icon: '⇄', label: 'Router / gateway' },
  firewall: { icon: '▣', label: 'Firewall' },
  printer:  { icon: '⎙', label: 'Printer' },
  nas:      { icon: '▤', label: 'NAS / storage' },
  camera:   { icon: '◉', label: 'Camera / NVR' },
  windows:  { icon: '⊞', label: 'Windows computer' },
  apple:    { icon: '⌘', label: 'Apple device' },
  phone:    { icon: '▯', label: 'Phone / tablet' },
  server:   { icon: '▥', label: 'Server' },
  linux:    { icon: '◆', label: 'Linux / Unix device' },
  media:    { icon: '▶', label: 'TV / media' },
  iot:      { icon: '◎', label: 'IoT / embedded' },
  ap:       { icon: '⌔', label: 'Wi-Fi access point / switch' },
  unknown:  { icon: '?', label: 'Unknown device' },
};

const V = (re) => (d) => re.test(d.vendor || '');
const H = (re) => (d) => re.test(`${d.hostname} ${d.deviceHint}`);
const P = (...ports) => (d) => ports.some((p) => d.ports.some((x) => x.port === p));
const S = (re) => (d) => d.ports.some((x) => re.test(`${x.service} ${x.version}`));
const any = (...fns) => (d) => fns.some((f) => f(d));

const RULES = [
  ['firewall', any(V(/fortinet|palo alto|sophos|watchguard|check point|netgate/i), H(/firewall|opnsense|pfsense|fortigate/i), S(/opnsense|pfsense|fortigate/i))],
  ['printer', any(P(9100, 515, 631), H(/printer|print/i), V(/hewlett|^hp\b|canon|brother|epson|lexmark|kyocera|xerox|ricoh|konica|oki data/i), S(/ipp|jetdirect|cups/i))],
  ['camera', any(P(554, 37777, 8554), H(/webcam|camera|ipcam|nvr|dvr/i), V(/hikvision|dahua|axis comm|hanwha|uniview|reolink|amcrest/i), S(/rtsp/i))],
  ['nas', any(V(/synology|qnap|western digital|seagate|buffalo|asustor|terramaster/i), H(/\bnas\b|storage|diskstation/i), P(5000, 5001, 2049) )],
  ['router', H(/router|gateway|\bgw\b|fritz/i)],
  ['ap', any(V(/ubiquiti|aruba|ruckus|cisco meraki|tp-link|zyxel|cambium|mikrotik|netgear|d-link|juniper/i), H(/switch|\bap\b|access point/i))],
  ['router', any(H(/router|gateway|\bgw\b|fritz|broadband/i), S(/dnsmasq|routeros|miniupnp|upnp/i), (d) => P(53)(d) && P(80, 443)(d))],
  ['phone', any(P(62078), H(/iphone|ipad|android|galaxy|pixel|phone/i))],
  ['apple', any(V(/^apple/i), H(/macbook|imac|mac-?mini|apple/i), S(/afp|apple/i), P(548, 7000))],
  ['windows', any(P(135, 139, 445, 3389), H(/windows|desktop-|laptop-|win-/i), (d) => /windows/i.test(d.os))],
  ['media', any(V(/samsung electronics|lg electronics|sony|roku|sonos|amazon|google/i), H(/\btv\b|chromecast|roku|sonos|firetv|appletv/i), P(8008, 8009, 1400))],
  ['server', any(P(25, 110, 143, 389, 636, 1433, 1521, 3306, 5432, 27017, 6379, 9200), H(/server|srv|\bdc\d*\b|mail|db/i))],
  ['iot', any(V(/espressif|raspberry|tuya|shelly|sonoff|arduino|texas instruments|silicon labs|nordic/i), P(1883, 8883, 5683))],
  ['linux', any(P(22), (d) => /linux|unix|bsd/i.test(d.os))],
];

// "Service Info: Device: …" od nmapu ma prednost pred odhadom.
const NMAP_DEVICE = [
  [/firewall|security-misc/i, 'firewall'],
  [/router/i, 'router'],
  [/printer/i, 'printer'],
  [/webcam|camera/i, 'camera'],
  [/storage/i, 'nas'],
  [/switch|wap|bridge/i, 'ap'],
  [/phone/i, 'phone'],
  [/media|game console/i, 'media'],
];

export function classifyDevice(d) {
  const hint = NMAP_DEVICE.find(([re]) => re.test(d.deviceHint || ''));
  if (hint) return hint[1];
  for (const [type, test] of RULES) if (test(d)) return type;
  return 'unknown';
}

/** Kompletny inventar: zariadenia + ARP + typ, zoradene podla IP. */
export function buildInventory(text, arp = []) {
  return mergeArp(parseInventory(text), arp)
    .map((d) => ({ ...d, type: classifyDevice(d) }))
    .sort((a, b) => ipNum(a.ip) - ipNum(b.ip));
}

export function ipNum(ip) {
  const p = String(ip).split('.').map(Number);
  return p.length === 4 && p.every((n) => n >= 0 && n <= 255) ? ((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3] : Number.MAX_SAFE_INTEGER;
}

// ─── Export CSV ───────────────────────────────────────────────────────────────
// Bunky zacinajuce na = + - @ by Excel vyhodnotil ako vzorec → apostrof pred.
const csvCell = (v) => {
  let s = String(v ?? '');
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

export function inventoryCsv(devices) {
  const head = ['IP', 'Hostname', 'MAC', 'Vendor', 'Type', 'OS', 'Open ports', 'Latency ms'];
  const rows = devices.map((d) => [
    d.ip, d.hostname, d.mac, d.randomizedMac ? 'randomized MAC' : d.vendor, DEVICE_TYPES[d.type]?.label || d.type, d.os,
    d.ports.map((p) => `${p.port}/${p.proto} ${p.service}`).join(' | '), d.latencyMs ?? '',
  ]);
  return [head, ...rows].map((r) => r.map(csvCell).join(',')).join('\n');
}

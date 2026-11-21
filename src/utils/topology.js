import { SEVERITY_ORDER } from './findings';
import { getPortRisk } from '../data/portRisk';
import { ipNum } from './inventory';

// ─── Mapa siete ───────────────────────────────────────────────────────────────
// Z inventara zariadeni zostavi topologiu "hviezda": internet → router (brana)
// → skupiny zariadeni podla typu. Kazde zariadenie dostane uroven rizika podla
// najzavaznejsieho nalezu, pripadne podla rizikovych otvorenych portov.

// Poradie skupin v mape (infrastruktura → pocitace → ostatne).
const GROUP_ORDER = ['firewall', 'ap', 'server', 'nas', 'windows', 'apple', 'linux', 'printer', 'camera', 'phone', 'media', 'iot', 'router', 'unknown'];

/** IP z retazca hostitela nalezu: "nazov (10.0.0.5)" alebo "10.0.0.5". */
export function hostIp(host) {
  const s = String(host || '');
  const m = s.match(/\((\d{1,3}(?:\.\d{1,3}){3})\)\s*$/);
  return m ? m[1] : s.trim();
}

/**
 * Riziko zariadenia: 'critical' | 'high' | 'medium' | 'low' (nalezy),
 * 'exposed' (len rizikove porty, napr. SMB, RDP, Telnet) alebo 'ok'.
 */
export function deviceRisk(device, findings = []) {
  const own = findings.filter((f) => hostIp(f.host) === device.ip);
  if (own.length) {
    const worst = own.reduce((a, f) => (SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[a] ? f.severity : a), 'low');
    return { level: worst, findings: own.length, exploited: own.some((f) => f.exploited) };
  }
  const risky = device.ports.filter((p) => getPortRisk(p.port) === 'high').map((p) => p.port);
  return { level: risky.length ? 'exposed' : 'ok', findings: 0, exploited: false, riskyPorts: risky };
}

/** CIDR rozsahy zo zadaneho ciela ("10.0.0.0/22 192.168.5.0/24") → [{ cidr, net, mask }]. */
export function targetNetworks(target) {
  return String(target || '').split(/[\s,]+/).map((tok) => {
    const m = tok.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
    if (!m || Number(m[2]) > 32) return null;
    const ip = ipNum(m[1]);
    if (ip === Number.MAX_SAFE_INTEGER) return null;
    const size = 2 ** (32 - Number(m[2]));
    return { cidr: tok, net: Math.floor(ip / size) * size, size };
  }).filter(Boolean);
}

const sameNet24 = (a, b) => String(a).split('.').slice(0, 3).join('.') === String(b).split('.').slice(0, 3).join('.');

/**
 * @param {{ devices: Array, gatewayIp?: string|null, localIps?: string[], findings?: Array }} o
 * @returns {{ gateway: object|null, groups: Array<{ type, devices }>, counts: object }}
 */
export function buildTopology({ devices = [], gatewayIp = null, localIps = [], findings = [], target = '' }) {
  const local = new Set(localIps);
  const nodes = devices.map((d) => ({ ...d, isSelf: local.has(d.ip), risk: deviceRisk(d, findings) }));

  // Brana: skutocna predvolena brana systemu, inak router s .1 / .254, inak prvy router.
  let gateway = nodes.find((d) => d.ip === gatewayIp) || null;
  if (!gateway) {
    const routers = nodes.filter((d) => d.type === 'router' || d.type === 'firewall');
    gateway = routers.find((d) => /\.(1|254)$/.test(d.ip)) || routers[0] || null;
  }
  if (!gateway && gatewayIp && nodes.some((d) => sameNet24(d.ip, gatewayIp))) {
    gateway = { ip: gatewayIp, hostname: '', type: 'router', ports: [], mac: '', vendor: '', synthetic: true, risk: { level: 'ok', findings: 0 } };
  }

  const rank = (t) => { const i = GROUP_ORDER.indexOf(t); return i < 0 ? GROUP_ORDER.length : i; };
  const groupBy = (list) => {
    const byType = new Map();
    list.forEach((d) => {
      if (!byType.has(d.type)) byType.set(d.type, []);
      byType.get(d.type).push(d);
    });
    return [...byType].map(([type, l]) => ({ type, devices: l.sort((a, b) => ipNum(a.ip) - ipNum(b.ip)) }))
      .sort((a, b) => rank(a.type) - rank(b.type));
  };
  const members = nodes.filter((d) => d !== gateway);
  const groups = groupBy(members);

  // Segmenty: kazdy zadany rozsah (CIDR) vlastny ramcek; jeden rozsah = jeden ramcek
  // (napr. 10.0.0.0/22 = jedna siet, aj ked ma viac ako 254 adries).
  const nets = targetNetworks(target);
  let segments;
  if (nets.length < 2) {
    segments = [{ label: target || '', groups, total: members.length }];
  } else {
    const buckets = nets.map((n) => ({ ...n, list: [] }));
    const other = [];
    members.forEach((d) => {
      const ip = ipNum(d.ip);
      const b = buckets.find((n) => ip >= n.net && ip < n.net + n.size);
      (b ? b.list : other).push(d);
    });
    segments = buckets.filter((b) => b.list.length).map((b) => ({ label: b.cidr, groups: groupBy(b.list), total: b.list.length }));
    if (other.length) segments.push({ label: '', other: true, groups: groupBy(other), total: other.length });
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0, exposed: 0, ok: 0 };
  nodes.forEach((d) => { counts[d.risk.level] += 1; });
  return { gateway, groups, segments, counts, total: nodes.length };
}

// Detekcia lokalnych IPv4 sieti (bez zavislosti na electron, testovatelne samostatne).
const os = require('os');

function ipToInt(ip) {
  return ip.split('.').reduce((acc, o) => ((acc << 8) | Number(o)) >>> 0, 0) >>> 0;
}
function intToIp(n) {
  return [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');
}
function prefixFromMask(mask) {
  const n = ipToInt(mask);
  let bits = 0;
  for (let i = 31; i >= 0 && ((n >>> i) & 1); i--) bits++;
  // maska musi byt suvisla (napr. 255.255.255.0), inak ju zahodime
  const expected = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return n === expected ? bits : null;
}
function networkOf(ip, prefix) {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return `${intToIp((ipToInt(ip) & mask) >>> 0)}/${prefix}`;
}
function isPrivate(ip) {
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

/**
 * @param {Record<string, os.NetworkInterfaceInfo[]>} [ifaces]
 * @returns {Array<{iface,address,prefix,cidr,suggested,isPrivate,virtual}>}
 */
function detectNetworks(ifaces = os.networkInterfaces()) {
  const out = [];
  for (const [iface, list] of Object.entries(ifaces || {})) {
    for (const a of list || []) {
      if (a.family !== 'IPv4' || a.internal) continue;
      if (a.address.startsWith('169.254.')) continue; // link-local, ziadna realna siet
      const prefix = prefixFromMask(a.netmask);
      if (prefix === null || prefix >= 32) continue;
      const cidr = networkOf(a.address, prefix);
      out.push({
        iface,
        address: a.address,
        prefix,
        cidr,
        // siete sirsie ako /24 (napr. 10.0.0.0/8) by boli obrovsky sken,
        // preto navrhneme len /24 okolo nasej adresy
        suggested: prefix < 24 ? networkOf(a.address, 24) : cidr,
        isPrivate: isPrivate(a.address),
        virtual: /^(utun|awdl|llw|bridge|vmnet|vnic|docker|veth|tailscale|zt)/i.test(iface),
      });
    }
  }
  // prednost: privatne a nie virtualne, potom en0, en1, ...
  out.sort((x, y) =>
    Number(y.isPrivate) - Number(x.isPrivate) ||
    Number(x.virtual) - Number(y.virtual) ||
    x.iface.localeCompare(y.iface, undefined, { numeric: true })
  );
  return out;
}

module.exports = { detectNetworks, prefixFromMask, networkOf };

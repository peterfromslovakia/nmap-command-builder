// ─── Sieťové nástroje (TOOLS záložka) ────────────────────────────────────────
// WHOIS, DNS lookup, SSL certifikát, IP geolokácia (ipinfo.io — bez kľúča).
// Všetko cez Node.js built-in moduly — žiadne extra npm závislosti.

const net  = require('net');
const dns  = require('dns').promises;
const tls  = require('tls');
const https = require('https');

// ─── WHOIS ────────────────────────────────────────────────────────────────────

function whoisQuery(query, server, timeout = 10000) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(43, server);
    let data = '';
    const timer = setTimeout(() => { sock.destroy(); reject(new Error('timeout')); }, timeout);
    sock.setEncoding('utf8');
    sock.on('connect', () => sock.write(query + '\r\n'));
    sock.on('data', (c) => { data += c; });
    sock.on('end', () => { clearTimeout(timer); resolve(data); });
    sock.on('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

function findReferral(text) {
  for (const line of text.split('\n')) {
    const m = line.match(/^(?:refer|ReferralServer):\s*(?:whois:\/\/)?(\S+)/i);
    if (m) return m[1].trim().replace(/:\d+$/, '');
  }
  return null;
}

async function whoisLookup(query) {
  const q = String(query || '').trim();
  if (!q) return 'No query entered.';

  // Prvý server: IANA (pre IP aj domény)
  const start = /^\d/.test(q) ? 'whois.iana.org' : 'whois.iana.org';
  let text = await whoisQuery(q, start);
  let referral = findReferral(text);

  // Sledovanie referralu — max 2 skoky
  for (let i = 0; i < 2 && referral; i++) {
    const next = await whoisQuery(q, referral).catch(() => null);
    if (!next) break;
    text = next;
    referral = findReferral(text);
  }
  return text || '(no data returned)';
}

// ─── DNS lookup ───────────────────────────────────────────────────────────────

const DNS_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR'];

async function dnsLookup(host, type) {
  const h = String(host || '').trim();
  if (!h) return { error: 'No host entered.' };

  const run = async (t) => {
    try {
      switch (t) {
        case 'A':     return { type: t, records: await dns.resolve4(h) };
        case 'AAAA':  return { type: t, records: await dns.resolve6(h) };
        case 'MX':    return { type: t, records: await dns.resolveMx(h) };
        case 'NS':    return { type: t, records: await dns.resolveNs(h) };
        case 'TXT':   return { type: t, records: await dns.resolveTxt(h) };
        case 'CNAME': return { type: t, records: await dns.resolveCname(h) };
        case 'SOA':   return { type: t, records: [await dns.resolveSoa(h)] };
        case 'PTR':   return { type: t, records: await dns.reverse(h) };
        default:      return { type: t, error: 'Unknown type' };
      }
    } catch (e) {
      return { type: t, error: e.code || e.message };
    }
  };

  if (type === 'ALL') {
    const results = await Promise.all(DNS_TYPES.map(run));
    return { type: 'ALL', results: results.filter((r) => !r.error || r.error !== 'ENODATA') };
  }
  return run(type || 'A');
}

// ─── SSL certifikát ──────────────────────────────────────────────────────────

function sslCheck(host, port) {
  const h = String(host || '').trim();
  const p = Number(port) || 443;
  if (!h) return Promise.resolve({ error: 'No host entered.' });

  return new Promise((resolve) => {
    const sock = tls.connect({ host: h, port: p, rejectUnauthorized: false, timeout: 10000 }, () => {
      const cert = sock.getPeerCertificate(true);
      sock.end();
      if (!cert || !cert.subject) return resolve({ error: 'No certificate returned.' });

      const now = Date.now();
      const validTo = new Date(cert.valid_to);
      const daysLeft = Math.round((validTo - now) / 86400000);

      resolve({
        subject:     cert.subject ? formatDN(cert.subject) : '—',
        issuer:      cert.issuer  ? formatDN(cert.issuer)  : '—',
        validFrom:   cert.valid_from || '—',
        validTo:     cert.valid_to   || '—',
        daysLeft,
        expired:     daysLeft < 0,
        fingerprint: cert.fingerprint256 || cert.fingerprint || '—',
        sans:        cert.subjectaltname || '—',
        serialNumber: cert.serialNumber || '—',
      });
    });
    sock.on('error', (e) => resolve({ error: e.message }));
    sock.on('timeout', () => { sock.destroy(); resolve({ error: 'Connection timed out.' }); });
  });
}

function formatDN(obj) {
  return Object.entries(obj).map(([k, v]) => `${k}=${v}`).join(', ');
}

// ─── IP geolokácia (ipinfo.io — zadarmo, bez kľúča) ─────────────────────────

function ipInfo(ip) {
  const q = String(ip || '').trim();
  if (!q) return Promise.resolve({ error: 'No IP entered.' });
  const url = `https://ipinfo.io/${encodeURIComponent(q)}/json`;

  return new Promise((resolve) => {
    const req = https.get(url, { headers: { 'User-Agent': 'nmap-command-builder/1.0' } }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { body += c; });
      res.on('end', () => {
        try {
          const d = JSON.parse(body);
          if (d.error) return resolve({ error: d.error.message || 'API error' });
          resolve(d);
        } catch (e) {
          resolve({ error: 'Could not parse response.' });
        }
      });
    });
    req.setTimeout(10000, () => { req.destroy(); resolve({ error: 'Request timed out.' }); });
    req.on('error', (e) => resolve({ error: e.message }));
  });
}

// ─── Registrácia IPC handlerov ────────────────────────────────────────────────

exports.register = function (ipcMain, isTrusted) {
  ipcMain.handle('tools:whois', async (event, { query } = {}) => {
    if (!isTrusted(event)) return { error: 'Untrusted sender.' };
    try { return { output: await whoisLookup(query) }; }
    catch (e) { return { error: e.message }; }
  });

  ipcMain.handle('tools:dns', async (event, { host, type } = {}) => {
    if (!isTrusted(event)) return { error: 'Untrusted sender.' };
    try { return await dnsLookup(host, type); }
    catch (e) { return { error: e.message }; }
  });

  ipcMain.handle('tools:ssl', async (event, { host, port } = {}) => {
    if (!isTrusted(event)) return { error: 'Untrusted sender.' };
    return sslCheck(host, port);
  });

  ipcMain.handle('tools:ipinfo', async (event, { ip } = {}) => {
    if (!isTrusted(event)) return { error: 'Untrusted sender.' };
    return ipInfo(ip);
  });
};

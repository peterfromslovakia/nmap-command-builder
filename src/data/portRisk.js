// ─── Port Risk Classification ─────────────────────────────────────────────────
// Used by PortsPanel and IntelPanel to visually classify open ports.
//
// 'high'   — cleartext protocols, direct remote access, known-dangerous exposure
// 'medium' — management or auxiliary services that warrant review
// 'safe'   — standard encrypted/web services (still worth checking config)

const PORT_RISK_MAP = {
  // ── HIGH ──────────────────────────────────────────────────────────────────
  21:    'high',   // FTP — cleartext credentials
  23:    'high',   // Telnet — cleartext session
  135:   'high',   // MS-RPC — Windows lateral movement surface
  139:   'high',   // NetBIOS — legacy Windows exposure
  445:   'high',   // SMB — ransomware / lateral movement (EternalBlue)
  3389:  'high',   // RDP — direct remote desktop (BlueKeep)
  5900:  'high',   // VNC — graphical remote, often unencrypted
  6379:  'high',   // Redis — commonly unauthenticated by default
  27017: 'high',   // MongoDB — commonly unauthenticated by default
  9200:  'high',   // Elasticsearch — often no auth, full data exposure
  2375:  'high',   // Docker daemon (unencrypted) — full host takeover
  2379:  'high',   // etcd — Kubernetes secrets store

  // ── MEDIUM ────────────────────────────────────────────────────────────────
  22:    'medium', // SSH — encrypted but exposed; check auth methods
  25:    'medium', // SMTP — check for open relay
  53:    'medium', // DNS — check recursion, zone transfer
  110:   'medium', // POP3 — cleartext mail retrieval
  143:   'medium', // IMAP — cleartext mail
  161:   'medium', // SNMP — community string exposure
  389:   'medium', // LDAP — directory exposure
  512:   'medium', // rexec — remote execution (legacy)
  513:   'medium', // rlogin — remote login (legacy)
  514:   'medium', // rsh/syslog — legacy remote shell
  3306:  'medium', // MySQL — DB should not be network-exposed
  5432:  'medium', // PostgreSQL — DB should not be network-exposed
  5984:  'medium', // CouchDB — check admin access
  6443:  'medium', // Kubernetes API
  8080:  'medium', // HTTP-alt — often admin panels / dev servers
  8443:  'medium', // HTTPS-alt — often admin panels / app servers
  8888:  'medium', // Jupyter Notebook — often no auth in dev
  9090:  'medium', // Prometheus / Cockpit

  // ── SAFE (default — not in this map) ──────────────────────────────────────
  80:    'safe',   // HTTP — standard web
  443:   'safe',   // HTTPS — encrypted web
  993:   'safe',   // IMAPS
  995:   'safe',   // POP3S
  587:   'safe',   // SMTP submission (TLS)
};

/**
 * Returns the risk level for a given port number.
 * @param {string|number} port
 * @returns {'high' | 'medium' | 'safe'}
 */
export function getPortRisk(port) {
  return PORT_RISK_MAP[parseInt(port, 10)] || 'safe';
}

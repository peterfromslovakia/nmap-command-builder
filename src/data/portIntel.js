// ─── Port Intelligence Data ───────────────────────────────────────────────────
// Lightweight informational hints for common ports.
// Each entry: { label, risk, hints[], scripts[], followUp[{label, cmd}] }
//
// followUp cmd uses {target} as a placeholder for the scanned target.
// Kept intentionally compact: 1 risk note, 1-2 hints, 1-3 NSE suggestions.

const PORT_INTEL_MAP = {
  21: {
    label: 'FTP',
    risk: 'Cleartext protocol — credentials and data transmitted unencrypted.',
    hints: ['Check for anonymous login', 'FTP bounce scan may be possible'],
    scripts: ['ftp-anon', 'ftp-bounce'],
    followUp: [
      { label: 'Anonymous login check', cmd: 'nmap --script ftp-anon -p 21 {target}' },
      { label: 'Service version', cmd: 'nmap -sV -p 21 {target}' },
    ],
  },
  22: {
    label: 'SSH',
    risk: 'SSH exposed — enumerate auth methods and supported algorithms.',
    hints: ['Check if password auth is enabled', 'Outdated key exchange algos weaken security'],
    scripts: ['ssh-auth-methods', 'ssh2-enum-algos'],
    followUp: [
      { label: 'Auth methods', cmd: 'nmap --script ssh-auth-methods -p 22 {target}' },
      { label: 'Key exchange algos', cmd: 'nmap --script ssh2-enum-algos -p 22 {target}' },
    ],
  },
  23: {
    label: 'Telnet',
    risk: 'Cleartext remote access — passwords visible in transit.',
    hints: ['Replace with SSH immediately', 'Common on embedded/IoT devices'],
    scripts: ['telnet-ntlm-info'],
    followUp: [
      { label: 'Service banner', cmd: 'nmap -sV --script telnet-ntlm-info -p 23 {target}' },
    ],
  },
  25: {
    label: 'SMTP',
    risk: 'SMTP exposed — check for open relay and user enumeration.',
    hints: ['Open relay allows spam abuse', 'VRFY/EXPN may leak valid usernames'],
    scripts: ['smtp-open-relay', 'smtp-commands'],
    followUp: [
      { label: 'Open relay check', cmd: 'nmap --script smtp-open-relay -p 25 {target}' },
      { label: 'SMTP commands', cmd: 'nmap --script smtp-commands -p 25 {target}' },
    ],
  },
  53: {
    label: 'DNS',
    risk: 'DNS exposed — check open recursion and zone transfer.',
    hints: ['Open recursion enables amplification attacks', 'Zone transfer may reveal full topology'],
    scripts: ['dns-recursion', 'dns-zone-transfer'],
    followUp: [
      { label: 'Recursion check', cmd: 'nmap --script dns-recursion -p 53 {target}' },
      { label: 'Zone transfer', cmd: 'nmap --script dns-zone-transfer -p 53 {target}' },
    ],
  },
  80: {
    label: 'HTTP',
    risk: 'Cleartext web service — enumerate paths and headers.',
    hints: ['Check for admin panels and sensitive endpoints', 'HTTP headers may reveal server stack'],
    scripts: ['http-title', 'http-enum', 'http-headers'],
    followUp: [
      { label: 'Title + headers', cmd: 'nmap --script http-title,http-headers -p 80 {target}' },
      { label: 'Web enumeration', cmd: 'nmap --script http-enum -p 80 {target}' },
      { label: 'HTTP methods', cmd: 'nmap --script http-methods -p 80 {target}' },
    ],
  },
  110: {
    label: 'POP3',
    risk: 'Cleartext mail retrieval — use POP3S (995) instead.',
    hints: ['Credentials sent unencrypted', 'NTLM auth may leak domain info'],
    scripts: ['pop3-capabilities', 'pop3-ntlm-info'],
    followUp: [
      { label: 'POP3 capabilities', cmd: 'nmap --script pop3-capabilities -p 110 {target}' },
    ],
  },
  135: {
    label: 'MS-RPC',
    risk: 'Windows RPC endpoint mapper — lateral movement surface.',
    hints: ['Common vector in Windows network attacks', 'Enumerate exposed endpoints'],
    scripts: ['msrpc-enum'],
    followUp: [
      { label: 'RPC endpoint enum', cmd: 'nmap --script msrpc-enum -p 135 {target}' },
      { label: 'Version detection', cmd: 'nmap -sV -p 135 {target}' },
    ],
  },
  139: {
    label: 'NetBIOS',
    risk: 'NetBIOS exposed — legacy Windows networking, leaks host info.',
    hints: ['Reveals machine name and workgroup', 'Combine with SMB (445) checks'],
    scripts: ['nbstat', 'smb-os-discovery'],
    followUp: [
      { label: 'NetBIOS stat', cmd: 'nmap --script nbstat -p 139 {target}' },
      { label: 'OS via SMB', cmd: 'nmap --script smb-os-discovery -p 139,445 {target}' },
    ],
  },
  143: {
    label: 'IMAP',
    risk: 'Cleartext IMAP — use IMAPS (993) instead.',
    hints: ['Credentials sent unencrypted', 'Check supported authentication mechanisms'],
    scripts: ['imap-capabilities', 'imap-ntlm-info'],
    followUp: [
      { label: 'IMAP capabilities', cmd: 'nmap --script imap-capabilities -p 143 {target}' },
    ],
  },
  161: {
    label: 'SNMP',
    risk: 'SNMP exposed — community strings may reveal full system info.',
    hints: ['Default communities "public"/"private" are widely abused', 'Can expose interfaces, routing, running processes'],
    scripts: ['snmp-info', 'snmp-sysdescr'],
    followUp: [
      { label: 'SNMP system info', cmd: 'nmap -sU --script snmp-info -p 161 {target}' },
      { label: 'Interface list', cmd: 'nmap -sU --script snmp-interfaces -p 161 {target}' },
    ],
  },
  389: {
    label: 'LDAP',
    risk: 'LDAP exposed — may allow directory enumeration without credentials.',
    hints: ['Anonymous bind may be enabled', 'Can reveal users, groups, and OUs'],
    scripts: ['ldap-rootdse', 'ldap-search'],
    followUp: [
      { label: 'LDAP root DSE', cmd: 'nmap --script ldap-rootdse -p 389 {target}' },
    ],
  },
  443: {
    label: 'HTTPS',
    risk: 'Encrypted web — check TLS config and certificate validity.',
    hints: ['Weak cipher suites and old TLS versions are common', 'Certificate may reveal internal hostnames (SANs)'],
    scripts: ['ssl-cert', 'ssl-enum-ciphers'],
    followUp: [
      { label: 'SSL certificate', cmd: 'nmap --script ssl-cert -p 443 {target}' },
      { label: 'TLS cipher suites', cmd: 'nmap --script ssl-enum-ciphers -p 443 {target}' },
      { label: 'Web enumeration', cmd: 'nmap --script http-enum -p 443 {target}' },
    ],
  },
  445: {
    label: 'SMB',
    risk: 'SMB exposed — ransomware and lateral movement attack surface.',
    hints: ['EternalBlue (MS17-010) targets unpatched SMB', 'Enumerate shares for sensitive data'],
    scripts: ['smb-os-discovery', 'smb-enum-shares', 'smb-vuln-ms17-010'],
    followUp: [
      { label: 'OS discovery', cmd: 'nmap --script smb-os-discovery -p 445 {target}' },
      { label: 'Share enumeration', cmd: 'nmap --script smb-enum-shares -p 445 {target}' },
      { label: 'EternalBlue check', cmd: 'nmap --script smb-vuln-ms17-010 -p 445 {target}' },
    ],
  },
  3306: {
    label: 'MySQL',
    risk: 'MySQL database exposed to network — should be localhost-only.',
    hints: ['Check for empty root password', 'Network-exposed databases are high risk'],
    scripts: ['mysql-info', 'mysql-empty-password'],
    followUp: [
      { label: 'MySQL info', cmd: 'nmap --script mysql-info -p 3306 {target}' },
      { label: 'Empty password check', cmd: 'nmap --script mysql-empty-password -p 3306 {target}' },
    ],
  },
  3389: {
    label: 'RDP',
    risk: 'RDP exposed — direct remote desktop access to the system.',
    hints: ['BlueKeep (CVE-2019-0708) targets unpatched RDP', 'Brute-force surface if exposed to internet'],
    scripts: ['rdp-enum-encryption', 'rdp-vuln-ms12-020'],
    followUp: [
      { label: 'RDP encryption', cmd: 'nmap --script rdp-enum-encryption -p 3389 {target}' },
      { label: 'Version detection', cmd: 'nmap -sV -p 3389 {target}' },
    ],
  },
  5432: {
    label: 'PostgreSQL',
    risk: 'PostgreSQL exposed to network — should be localhost-only.',
    hints: ['Check peer/md5 authentication settings', 'Network-exposed databases are high risk'],
    scripts: ['pgsql-brute'],
    followUp: [
      { label: 'Version detection', cmd: 'nmap -sV -p 5432 {target}' },
    ],
  },
  5900: {
    label: 'VNC',
    risk: 'VNC exposed — full graphical remote access, often unencrypted.',
    hints: ['Authentication bypass is a known misconfiguration', 'Traffic may be cleartext'],
    scripts: ['vnc-info', 'realvnc-auth-bypass'],
    followUp: [
      { label: 'VNC info', cmd: 'nmap --script vnc-info -p 5900 {target}' },
      { label: 'Auth bypass check', cmd: 'nmap --script realvnc-auth-bypass -p 5900 {target}' },
    ],
  },
  6379: {
    label: 'Redis',
    risk: 'Redis exposed — default config has no authentication.',
    hints: ['Attackers can write files or execute via Lua', 'Bind to 127.0.0.1 in production'],
    scripts: ['redis-info'],
    followUp: [
      { label: 'Redis info', cmd: 'nmap --script redis-info -p 6379 {target}' },
      { label: 'Version detection', cmd: 'nmap -sV -p 6379 {target}' },
    ],
  },
  8080: {
    label: 'HTTP-alt',
    risk: 'Alternate HTTP — often admin panels, proxies, or dev servers.',
    hints: ['Tomcat manager, Jenkins, Jupyter commonly use 8080', 'Cleartext — check for sensitive admin endpoints'],
    scripts: ['http-title', 'http-enum'],
    followUp: [
      { label: 'Title + headers', cmd: 'nmap --script http-title,http-headers -p 8080 {target}' },
      { label: 'Web enumeration', cmd: 'nmap --script http-enum -p 8080 {target}' },
    ],
  },
  8443: {
    label: 'HTTPS-alt',
    risk: 'Alternate HTTPS — often management or application servers.',
    hints: ['Management interfaces commonly use 8443', 'SSL cert SANs may reveal internal hostnames'],
    scripts: ['ssl-cert', 'http-title'],
    followUp: [
      { label: 'SSL cert + title', cmd: 'nmap --script ssl-cert,http-title -p 8443 {target}' },
      { label: 'Web enumeration', cmd: 'nmap --script http-enum -p 8443 {target}' },
    ],
  },
  9200: {
    label: 'Elasticsearch',
    risk: 'Elasticsearch exposed — full index access often without auth.',
    hints: ['Default config has no authentication', 'Can expose entire database contents'],
    scripts: ['http-title'],
    followUp: [
      { label: 'Version + headers', cmd: 'nmap -sV --script http-headers -p 9200 {target}' },
    ],
  },
  27017: {
    label: 'MongoDB',
    risk: 'MongoDB exposed — older versions have no auth by default.',
    hints: ['Unauthenticated access common in misconfigured installs', 'Can expose entire database'],
    scripts: ['mongodb-info', 'mongodb-databases'],
    followUp: [
      { label: 'MongoDB info', cmd: 'nmap --script mongodb-info -p 27017 {target}' },
      { label: 'Database list', cmd: 'nmap --script mongodb-databases -p 27017 {target}' },
    ],
  },
};

/**
 * Returns intel data for a given port number, or null if no data exists.
 * @param {string|number} port
 * @returns {{ label, risk, hints, scripts, followUp } | null}
 */
export function getPortIntel(port) {
  return PORT_INTEL_MAP[parseInt(port, 10)] || null;
}

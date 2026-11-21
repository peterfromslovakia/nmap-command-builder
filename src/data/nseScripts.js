// ─── NSE script library ───────────────────────────────────────────────────────
//
// Kuratorovany vyber beznych NSE skriptov (nie kompletny zoznam ~600 skriptov).
// Kategorie su prevzate z oficialnej dokumentacie nmap.org/nsedoc.
// Riziko sa odvodzuje z kategorii (pozri scriptRisk), nie je ulozene rucne.

export const NSE_CATEGORIES = [
  { id: 'default',   description: 'Same set as -sC — useful, fast and reasonably safe' },
  { id: 'safe',      description: 'Will not crash services or use excessive bandwidth' },
  { id: 'discovery', description: 'Actively learn more about the network (shares, SNMP, DNS…)' },
  { id: 'version',   description: 'Extended version detection (used together with -sV)' },
  { id: 'vuln',      description: 'Check for specific known vulnerabilities' },
  { id: 'auth',      description: 'Deal with authentication credentials or bypassing them' },
  { id: 'broadcast', description: 'Discover hosts by broadcasting on the local network' },
  { id: 'external',  description: 'May send data to third-party services (whois, geo, vulners)' },
  { id: 'malware',   description: 'Test whether the target is infected by malware or backdoors' },
  { id: 'intrusive', description: 'Risky — may crash services, create logs or be seen as attack' },
  { id: 'brute',     description: 'Brute-force guessing of credentials' },
  { id: 'exploit',   description: 'Actively exploit a vulnerability' },
  { id: 'dos',       description: 'May cause denial of service on the target' },
  { id: 'fuzzer',    description: 'Send unexpected / randomized data to the target' },
];

// Kategorie, ktore sa v UI zobrazia len v ADV mode.
export const DANGEROUS_CATEGORIES = new Set(['brute', 'exploit', 'dos', 'fuzzer']);

/** 'safe' | 'intrusive' | 'dangerous' */
export function scriptRisk(categories) {
  if (categories.some((c) => DANGEROUS_CATEGORIES.has(c))) return 'dangerous';
  if (categories.includes('intrusive')) return 'intrusive';
  return 'safe';
}

const s = (name, service, categories, description, args = []) => ({
  name, service, categories, description, args, risk: scriptRisk(categories),
});

export const NSE_SCRIPTS = [
  // ── Generic ────────────────────────────────────────────────────────────────
  s('banner', 'any', ['discovery', 'safe'],
    'Grab the banner sent by an open TCP service'),
  s('vulners', 'any', ['vuln', 'safe', 'external'],
    'Look up known CVEs for detected service versions (requires -sV, queries vulners.com)',
    [{ key: 'mincvss', example: '7.0', description: 'Show only CVEs with CVSS ≥ value' }]),
  s('whois-ip', 'any', ['discovery', 'external', 'safe'],
    'Query regional WHOIS registries for the target IP owner'),
  s('traceroute-geolocation', 'any', ['discovery', 'external', 'safe'],
    'Geolocate each hop of a traceroute (use with --traceroute)'),

  // ── HTTP ───────────────────────────────────────────────────────────────────
  s('http-title', 'http', ['default', 'discovery', 'safe'],
    'Show the title of the default web page'),
  s('http-headers', 'http', ['discovery', 'safe'],
    'Show HTTP response headers of the web root'),
  s('http-server-header', 'http', ['version'],
    'Read the Server header to improve version detection'),
  s('http-methods', 'http', ['default', 'safe'],
    'List supported HTTP methods and flag risky ones (PUT, DELETE, TRACE)',
    [{ key: 'http-methods.url-path', example: '/', description: 'Path to test' }]),
  s('http-robots.txt', 'http', ['default', 'discovery', 'safe'],
    'Show disallowed entries in /robots.txt'),
  s('http-auth-finder', 'http', ['discovery', 'safe'],
    'Spider the site and find pages requiring authentication'),
  s('http-cookie-flags', 'http', ['default', 'safe', 'vuln'],
    'Check session cookies for missing HttpOnly / Secure flags'),
  s('http-git', 'http', ['default', 'safe', 'vuln'],
    'Detect an exposed .git repository in the web root'),
  s('http-enum', 'http', ['discovery', 'intrusive', 'vuln'],
    'Enumerate common directories and applications (admin panels, backups…)',
    [{ key: 'http-enum.basepath', example: '/', description: 'Base path to prepend' }]),
  s('http-wordpress-enum', 'http', ['discovery', 'intrusive'],
    'Enumerate WordPress themes and plugins'),
  s('http-slowloris-check', 'http', ['vuln', 'safe'],
    'Test whether the server is vulnerable to Slowloris (without attacking)'),
  s('http-vuln-cve2017-5638', 'http', ['vuln', 'intrusive'],
    'Apache Struts RCE (CVE-2017-5638) detection'),
  s('http-sql-injection', 'http', ['intrusive', 'vuln'],
    'Spider the site and probe forms for SQL injection'),
  s('http-shellshock', 'http', ['exploit', 'vuln', 'intrusive'],
    'Test CGI scripts for Shellshock (CVE-2014-6271)',
    [{ key: 'http-shellshock.uri', example: '/cgi-bin/test.cgi', description: 'CGI script to test' }]),
  s('http-brute', 'http', ['intrusive', 'brute'],
    'Brute-force HTTP basic / digest authentication',
    [{ key: 'http-brute.path', example: '/admin/', description: 'Protected path' }]),
  s('http-slowloris', 'http', ['dos', 'intrusive'],
    'Slowloris denial-of-service attack — will make the server unavailable'),

  // ── TLS / SSL ──────────────────────────────────────────────────────────────
  s('ssl-cert', 'tls', ['default', 'safe', 'discovery'],
    'Show the TLS certificate (subject, issuer, validity)'),
  s('ssl-enum-ciphers', 'tls', ['discovery', 'intrusive'],
    'List supported TLS versions and ciphers with a strength grade'),
  s('ssl-heartbleed', 'tls', ['vuln', 'safe'],
    'Detect OpenSSL Heartbleed (CVE-2014-0160)'),
  s('ssl-poodle', 'tls', ['vuln', 'safe'],
    'Detect SSLv3 POODLE (CVE-2014-3566)'),
  s('ssl-dh-params', 'tls', ['vuln', 'safe'],
    'Detect weak Diffie-Hellman parameters (Logjam)'),
  s('sslv2', 'tls', ['default', 'safe'],
    'Check whether obsolete SSLv2 is supported'),

  // ── SSH ────────────────────────────────────────────────────────────────────
  s('ssh-hostkey', 'ssh', ['safe', 'default', 'discovery'],
    'Show SSH host key fingerprints'),
  s('ssh2-enum-algos', 'ssh', ['safe', 'discovery'],
    'List supported key exchange, cipher and MAC algorithms'),
  s('ssh-auth-methods', 'ssh', ['auth', 'intrusive'],
    'List authentication methods accepted for a user',
    [{ key: 'ssh.user', example: 'root', description: 'Username to test' }]),
  s('ssh-brute', 'ssh', ['brute', 'intrusive'],
    'Brute-force SSH passwords'),

  // ── FTP / Telnet ───────────────────────────────────────────────────────────
  s('ftp-anon', 'ftp', ['default', 'auth', 'safe'],
    'Check whether anonymous FTP login is allowed'),
  s('ftp-syst', 'ftp', ['default', 'safe', 'discovery'],
    'Query FTP server SYST and STAT information'),
  s('ftp-vsftpd-backdoor', 'ftp', ['exploit', 'intrusive', 'malware', 'vuln'],
    'Test for the vsftpd 2.3.4 backdoor (executes a command if vulnerable)'),
  s('ftp-brute', 'ftp', ['intrusive', 'brute'],
    'Brute-force FTP passwords'),
  s('telnet-encryption', 'telnet', ['safe', 'discovery'],
    'Check whether Telnet supports encryption'),

  // ── SMB / Windows ──────────────────────────────────────────────────────────
  s('smb-os-discovery', 'smb', ['default', 'discovery', 'safe'],
    'Get OS, computer name, domain and workgroup over SMB'),
  s('smb-protocols', 'smb', ['discovery', 'safe'],
    'List supported SMB dialects (flags SMBv1)'),
  s('smb-security-mode', 'smb', ['default', 'discovery', 'safe'],
    'SMBv1 signing and authentication settings'),
  s('smb2-security-mode', 'smb', ['default', 'discovery', 'safe'],
    'SMBv2/3 message signing configuration'),
  s('smb-vuln-ms17-010', 'smb', ['vuln', 'safe'],
    'Detect EternalBlue (MS17-010)'),
  s('smb-enum-shares', 'smb', ['discovery', 'intrusive'],
    'List SMB shares and their permissions'),
  s('smb-enum-users', 'smb', ['auth', 'intrusive'],
    'Enumerate local user accounts'),
  s('smb-vuln-ms08-067', 'smb', ['intrusive', 'exploit', 'dos', 'vuln'],
    'Detect MS08-067 — may crash the target service'),
  s('smb-brute', 'smb', ['intrusive', 'brute'],
    'Brute-force SMB credentials (may lock accounts)'),
  s('nbstat', 'netbios', ['default', 'discovery', 'safe'],
    'NetBIOS name, MAC address and logged-in user'),
  s('rdp-ntlm-info', 'rdp', ['default', 'discovery', 'safe'],
    'Read domain / host names from RDP NTLM challenge'),
  s('rdp-enum-encryption', 'rdp', ['safe', 'discovery'],
    'List RDP security layers and encryption levels'),
  s('rdp-vuln-ms12-020', 'rdp', ['intrusive', 'vuln'],
    'Detect MS12-020 RDP vulnerability'),

  // ── DNS ────────────────────────────────────────────────────────────────────
  s('dns-recursion', 'dns', ['default', 'safe'],
    'Check whether the DNS server allows recursive queries'),
  s('dns-service-discovery', 'dns', ['default', 'discovery', 'safe'],
    'List services advertised via DNS-SD (mDNS / Bonjour)'),
  s('dns-zone-transfer', 'dns', ['intrusive', 'discovery'],
    'Attempt an AXFR zone transfer',
    [{ key: 'dns-zone-transfer.domain', example: 'example.com', description: 'Domain to transfer' }]),
  s('dns-brute', 'dns', ['intrusive', 'discovery'],
    'Guess subdomains with a wordlist',
    [{ key: 'dns-brute.domain', example: 'example.com', description: 'Domain to brute-force' }]),

  // ── Mail ───────────────────────────────────────────────────────────────────
  s('smtp-commands', 'smtp', ['default', 'discovery', 'safe'],
    'List SMTP extensions supported (EHLO)'),
  s('smtp-open-relay', 'smtp', ['discovery', 'intrusive', 'external'],
    'Test whether the server is an open mail relay'),
  s('smtp-enum-users', 'smtp', ['auth', 'intrusive'],
    'Enumerate users via VRFY / EXPN / RCPT TO'),

  // ── Databases ──────────────────────────────────────────────────────────────
  s('mysql-info', 'mysql', ['default', 'discovery', 'safe'],
    'MySQL version, protocol and capabilities'),
  s('mysql-empty-password', 'mysql', ['intrusive', 'auth'],
    'Check for root / anonymous accounts with empty password'),
  s('ms-sql-info', 'mssql', ['default', 'discovery', 'safe'],
    'Microsoft SQL Server instance information'),
  s('mongodb-info', 'mongodb', ['default', 'discovery', 'safe'],
    'MongoDB build and server status (often exposed without auth)'),
  s('redis-info', 'redis', ['discovery', 'safe'],
    'Redis version and configuration (often exposed without auth)'),

  // ── Infrastructure / IoT ───────────────────────────────────────────────────
  s('snmp-info', 'snmp', ['default', 'version', 'safe'],
    'Basic SNMPv3 engine information (requires -sU)'),
  s('snmp-sysdescr', 'snmp', ['default', 'discovery', 'safe'],
    'System description via SNMP (requires -sU)'),
  s('snmp-brute', 'snmp', ['intrusive', 'brute'],
    'Guess SNMP community strings (requires -sU)'),
  s('upnp-info', 'upnp', ['default', 'discovery', 'safe'],
    'Device information from UPnP (routers, NAS, smart TVs)'),
  s('vnc-info', 'vnc', ['default', 'discovery', 'safe'],
    'VNC protocol version and security types'),
  s('realvnc-auth-bypass', 'vnc', ['auth', 'safe', 'vuln'],
    'Detect RealVNC authentication bypass (CVE-2006-2369)'),
  s('rpcinfo', 'rpc', ['discovery', 'default', 'safe'],
    'List RPC services registered with portmapper'),
  s('nfs-showmount', 'nfs', ['discovery', 'safe'],
    'Show exported NFS shares'),
  s('sip-methods', 'sip', ['default', 'safe', 'discovery'],
    'List methods supported by a SIP (VoIP) server'),

  // ── Broadcast (target not required) ────────────────────────────────────────
  s('broadcast-dhcp-discover', 'broadcast', ['broadcast', 'safe'],
    'Send DHCPDISCOVER and show the offered lease (requires root)'),
  s('broadcast-upnp-info', 'broadcast', ['broadcast', 'safe'],
    'Find UPnP devices on the local network via multicast'),
];

export const NSE_SCRIPT_MAP = Object.fromEntries(NSE_SCRIPTS.map((x) => [x.name, x]));

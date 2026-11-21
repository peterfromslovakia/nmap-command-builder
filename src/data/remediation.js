// ─── Remediation guidance ─────────────────────────────────────────────────────
//
// 1) PORT_FIXES — vseobecne odporucania pre otvoreny port (hardening).
// 2) FINDING_RULES — konkretne nalezy rozpoznane vo vystupe NSE skriptov
//    (napr. "State: VULNERABLE") s krokmi na opravu.
//
// Odporucania su strucne a vseobecne; vzdy over postup v dokumentacii vyrobcu.

export const PORT_FIXES = {
  21: [
    'Disable FTP if not needed; use SFTP (over SSH) or FTPS instead',
    'Disable anonymous login (vsftpd: anonymous_enable=NO)',
    'Restrict access with a firewall to trusted IPs only',
  ],
  22: [
    'Disable password login, use keys only (PasswordAuthentication no)',
    'Disable root login (PermitRootLogin no)',
    'Keep OpenSSH updated; limit access via firewall or VPN; consider fail2ban',
  ],
  23: [
    'Disable Telnet completely and use SSH instead',
    'On routers / IoT devices turn off Telnet in the admin interface and update firmware',
  ],
  25: [
    'Allow relaying only for authenticated users or internal networks',
    'Disable VRFY and EXPN commands (Postfix: disable_vrfy_command = yes)',
    'Enforce STARTTLS for mail transport',
  ],
  53: [
    'Disable open recursion for external clients (BIND: allow-recursion { trusted; })',
    'Allow zone transfers (AXFR) only to secondary DNS servers',
    'Keep the DNS server software updated',
  ],
  80: [
    'Redirect all HTTP traffic to HTTPS (301) and enable HSTS',
    'Hide server version banners (Apache: ServerTokens Prod, nginx: server_tokens off)',
    'Remove default pages, test apps and directory listing',
  ],
  110: [
    'Use POP3S (port 995) and disable cleartext POP3',
    'Require TLS before authentication',
  ],
  135: [
    'Block MS-RPC (135) at the network perimeter',
    'Allow it only between trusted internal hosts via Windows Firewall',
  ],
  139: [
    'Disable NetBIOS over TCP/IP if not needed (network adapter → WINS settings)',
    'Block ports 137–139 at the firewall',
  ],
  143: [
    'Use IMAPS (port 993) and disable cleartext IMAP',
    'Require TLS before authentication',
  ],
  161: [
    'Use SNMPv3 with authentication and encryption; disable v1/v2c',
    'Change default community strings (public / private)',
    'Allow SNMP only from the monitoring server',
  ],
  389: [
    'Use LDAPS (636) or StartTLS; require LDAP signing and channel binding',
    'Disable anonymous binds',
  ],
  443: [
    'Disable TLS 1.0/1.1 and weak ciphers; allow TLS 1.2+ only',
    'Keep certificates valid and enable HSTS',
    'Test the configuration with ssl-enum-ciphers or SSL Labs',
  ],
  445: [
    'Never expose SMB to the internet; block 445 at the perimeter',
    'Disable SMBv1 (PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false)',
    'Require SMB signing and install all Windows security updates',
  ],
  512: ['Disable rexec; use SSH instead'],
  513: ['Disable rlogin; use SSH instead'],
  514: ['Disable rsh; if this is syslog, accept it only from known hosts'],
  2375: [
    'Never expose the Docker API without TLS — this gives full root access to the host',
    'Bind the daemon to the unix socket only, or enable TLS client certificates (port 2376)',
  ],
  2379: [
    'Enable client certificate authentication for etcd',
    'Allow access only from Kubernetes control plane nodes',
  ],
  3306: [
    'Bind MySQL to localhost (bind-address = 127.0.0.1) if remote access is not needed',
    'Remove anonymous users and set strong passwords (mysql_secure_installation)',
    'Allow access only from application servers via firewall',
  ],
  3389: [
    'Do not expose RDP to the internet; use VPN or RD Gateway',
    'Enable Network Level Authentication (NLA) and account lockout',
    'Install security updates (BlueKeep CVE-2019-0708)',
  ],
  5432: [
    'Set listen_addresses = \'localhost\' if remote access is not needed',
    'Use scram-sha-256 in pg_hba.conf and allow only specific hosts',
  ],
  5900: [
    'Do not expose VNC directly; tunnel it over SSH or VPN',
    'Set a strong VNC password and enable encryption',
  ],
  5984: [
    'Create an admin user (disable "admin party" mode)',
    'Bind CouchDB to localhost or restrict access via firewall',
  ],
  6379: [
    'Bind Redis to 127.0.0.1 and enable protected-mode yes',
    'Set a password (requirepass) or ACL users',
    'Rename or disable dangerous commands (CONFIG, FLUSHALL)',
  ],
  6443: [
    'Disable anonymous auth on the Kubernetes API (--anonymous-auth=false)',
    'Restrict API access to admin networks',
  ],
  8080: [
    'Do not expose admin panels (Tomcat manager, Jenkins) to untrusted networks',
    'Change default credentials and put the service behind HTTPS',
  ],
  8443: [
    'Restrict management interfaces to admin networks or VPN',
    'Change default credentials and keep the software updated',
  ],
  8888: [
    'Protect Jupyter with a token or password; never run it on 0.0.0.0 without auth',
  ],
  9200: [
    'Enable Elasticsearch security (xpack.security.enabled: true)',
    'Bind to localhost or a private network; never expose 9200 publicly',
  ],
  27017: [
    'Enable authentication (security.authorization: enabled)',
    'Bind to localhost (net.bindIp: 127.0.0.1) or a private network',
  ],
};

export function getPortFixes(port) {
  return PORT_FIXES[parseInt(port, 10)] || [];
}

// ─── Findings in NSE output ───────────────────────────────────────────────────
// match: regex testovany na kazdy riadok vystupu.
// severity: 'critical' | 'high' | 'medium' | 'low'

export const FINDING_RULES = [
  {
    id: 'ms17-010',
    match: /CVE-2017-0143|Remote Code Execution vulnerability in Microsoft SMBv1/i,
    requireVulnerable: true,
    title: 'EternalBlue — SMBv1 RCE (MS17-010)',
    severity: 'critical',
    fix: [
      'Install Microsoft security update MS17-010 (or any later cumulative update)',
      'Disable SMBv1 on all hosts',
      'Block port 445 from untrusted networks',
    ],
    refs: ['https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010'],
  },
  {
    id: 'ms08-067',
    match: /CVE-2008-4250|MS08-067/i,
    requireVulnerable: true,
    title: 'MS08-067 — Windows Server service RCE',
    severity: 'critical',
    fix: [
      'Install security update MS08-067; this OS is likely end-of-life — upgrade it',
      'Isolate the host from the network until patched',
    ],
  },
  {
    id: 'heartbleed',
    match: /CVE-2014-0160|Heartbleed/i,
    requireVulnerable: true,
    title: 'Heartbleed — OpenSSL memory disclosure',
    severity: 'critical',
    fix: [
      'Update OpenSSL to 1.0.1g or newer and restart affected services',
      'Revoke and reissue TLS certificates (private key may be leaked)',
      'Reset passwords and session tokens of users of this service',
    ],
  },
  {
    id: 'shellshock',
    match: /CVE-2014-6271|Shellshock/i,
    requireVulnerable: true,
    title: 'Shellshock — Bash remote code execution',
    severity: 'critical',
    fix: ['Update bash on the server', 'Remove unused CGI scripts'],
  },
  {
    id: 'struts',
    match: /CVE-2017-5638/i,
    requireVulnerable: true,
    title: 'Apache Struts RCE (CVE-2017-5638)',
    severity: 'critical',
    fix: ['Upgrade Apache Struts to 2.3.32 / 2.5.10.1 or newer'],
  },
  {
    id: 'vsftpd-backdoor',
    match: /CVE-2011-2523|vsFTPd version 2\.3\.4 backdoor/i,
    requireVulnerable: true,
    title: 'vsftpd 2.3.4 backdoor',
    severity: 'critical',
    fix: [
      'Treat the host as compromised — investigate and reinstall',
      'Install vsftpd from the official distribution repository',
    ],
  },
  {
    id: 'ms12-020',
    match: /CVE-2012-0152|CVE-2012-0002|MS12-020/i,
    requireVulnerable: true,
    title: 'MS12-020 — RDP vulnerability',
    severity: 'high',
    fix: ['Install security update MS12-020', 'Enable Network Level Authentication (NLA)'],
  },
  {
    id: 'realvnc-bypass',
    match: /CVE-2006-2369|RealVNC 4\.1\.1 Authentication Bypass/i,
    requireVulnerable: true,
    title: 'RealVNC authentication bypass',
    severity: 'critical',
    fix: ['Upgrade RealVNC to 4.1.2 or newer', 'Do not expose VNC to the network directly'],
  },
  {
    id: 'poodle',
    match: /CVE-2014-3566|SSL POODLE/i,
    requireVulnerable: true,
    title: 'POODLE — SSLv3 enabled',
    severity: 'medium',
    fix: ['Disable SSLv3 on the server (allow TLS 1.2+ only)'],
  },
  {
    id: 'logjam',
    match: /Diffie-Hellman Key Exchange Insufficient Group Strength|CVE-2015-4000/i,
    requireVulnerable: true,
    title: 'Weak Diffie-Hellman parameters (Logjam)',
    severity: 'medium',
    fix: [
      'Generate DH parameters of 2048 bits or more (openssl dhparam 2048)',
      'Prefer ECDHE cipher suites; disable export ciphers',
    ],
  },
  {
    id: 'slowloris',
    match: /Slowloris DOS attack/i,
    requireVulnerable: true,
    title: 'Vulnerable to Slowloris DoS',
    severity: 'medium',
    fix: [
      'Limit connection / header timeouts (Apache: mod_reqtimeout, nginx: client_header_timeout)',
      'Put the server behind a reverse proxy or load balancer',
    ],
  },
  {
    id: 'ftp-anon',
    match: /Anonymous FTP login allowed/i,
    title: 'Anonymous FTP login allowed',
    severity: 'high',
    fix: [
      'Disable anonymous login (vsftpd: anonymous_enable=NO, ProFTPD: remove <Anonymous> block)',
      'If anonymous access is intended, make it read-only and not writable',
    ],
  },
  {
    id: 'sslv2',
    match: /SSLv2 supported/i,
    title: 'Obsolete SSLv2 enabled',
    severity: 'high',
    fix: ['Disable SSLv2 and SSLv3; allow TLS 1.2+ only'],
  },
  {
    id: 'weak-tls',
    match: /least strength: [C-F]\b/,
    title: 'Weak TLS ciphers offered',
    severity: 'medium',
    fix: [
      'Remove weak ciphers (RC4, 3DES, NULL, EXPORT) and TLS 1.0/1.1',
      'Use a modern profile, e.g. Mozilla SSL Configuration Generator "intermediate"',
    ],
  },
  {
    id: 'smbv1',
    match: /NT LM 0\.12 \(SMBv1\)|SMBv1.*dangerous/i,
    title: 'SMBv1 protocol enabled',
    severity: 'high',
    fix: [
      'Windows: Set-SmbServerConfiguration -EnableSMB1Protocol $false',
      'Samba: server min protocol = SMB2',
    ],
  },
  {
    id: 'smb-signing',
    match: /Message signing enabled but not required|message_signing: disabled/i,
    title: 'SMB signing not required',
    severity: 'medium',
    fix: [
      'Enable "Microsoft network server: Digitally sign communications (always)" in Group Policy',
      'Samba: server signing = mandatory',
    ],
  },
  {
    id: 'http-git',
    match: /Git repository found/i,
    title: 'Exposed .git repository',
    severity: 'high',
    fix: [
      'Remove the .git directory from the web root or deny access to /.git',
      'Rotate any secrets (passwords, API keys) that were in the repository',
    ],
  },
  {
    id: 'http-methods',
    match: /Potentially risky methods:.*\b(PUT|DELETE|TRACE|CONNECT)\b/i,
    title: 'Risky HTTP methods enabled',
    severity: 'medium',
    fix: [
      'Allow only GET, HEAD, POST (Apache: <LimitExcept>, nginx: limit_except)',
      'Disable TRACE (Apache: TraceEnable off)',
    ],
  },
  {
    id: 'dns-recursion',
    match: /Recursion appears to be enabled/i,
    title: 'Open DNS recursion',
    severity: 'medium',
    fix: [
      'Allow recursion only for internal clients (BIND: allow-recursion { trusted; };)',
      'Prevents use of the server in DNS amplification attacks',
    ],
  },
  {
    id: 'dns-axfr',
    match: /dns-zone-transfer:\s*$/i,
    title: 'DNS zone transfer allowed',
    severity: 'medium',
    fix: ['Allow AXFR only to secondary name servers (BIND: allow-transfer { <ip>; };)'],
  },
  {
    id: 'smtp-relay',
    match: /Server is an open relay/i,
    title: 'Open SMTP relay',
    severity: 'high',
    fix: [
      'Restrict relaying to authenticated users and internal networks',
      'Postfix: smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination',
    ],
  },
  {
    id: 'mysql-empty',
    match: /account has empty password/i,
    title: 'MySQL account with empty password',
    severity: 'critical',
    fix: [
      'Set passwords for all accounts or remove anonymous users (mysql_secure_installation)',
      'Do not expose MySQL to the network',
    ],
  },
  {
    id: 'cookie-flags',
    match: /httponly flag not set|secure flag not set/i,
    title: 'Session cookie missing HttpOnly / Secure flag',
    severity: 'low',
    fix: ['Set HttpOnly and Secure (and SameSite) attributes on session cookies'],
  },
];

// Fallback pre ine "VULNERABLE" nalezy bez specifickej rady.
export const GENERIC_VULN_FIX = [
  'Look up the CVE / advisory in the script output and apply the vendor patch',
  'Update the affected service to the latest supported version',
  'Until patched, restrict access to the port with a firewall',
];

export const CVE_FIX = [
  'Update the service to the latest version from the vendor / distribution',
  'Check each CVE for exploitability in your configuration (links below)',
  'Restrict network access to the service until updated',
];

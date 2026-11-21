# Changelog

## 1.1.0 — 2026-11-21

### New
- **Vulnerabilities & Fixes panel** — after a scan, NSE script output is analysed for known issues (EternalBlue / MS17-010, Heartbleed, POODLE, Shellshock, vsftpd backdoor, anonymous FTP, SMBv1, SMB signing, open SMTP relay, weak TLS, risky HTTP methods, open DNS recursion, MySQL empty password, CVEs from `vulners`, …) and each finding shows step-by-step remediation
- **"How to fix" hardening steps** for 31 risky ports in Security Intel
- **PDF and Markdown reports** — summary, findings with fixes, open ports per host, hardening recommendations and raw output
- **NSE script library** (SCRIPTS tab) — 71 curated scripts and all categories with search, risk badges and one-click `--script` / `--script-args`
- **10 new scan presets** — CVE Lookup, TLS/SSL Audit, SMB Security Check, Remote Access Audit, Database Exposure, DNS Server Check, Web Vulnerability Scan, Firewall Mapping, Credential Brute-force and Dangerous Vuln Checks (last two in Advanced mode only)
- **Risk labels for all presets** — LOW / NOISY / INTRUSIVE with an explanation
- **Automatic local network detection** pre-fills the target

### Improved
- Larger font and higher-contrast text across the app
- Wider left panel that scales with the window
- Result panels scroll together, the terminal always stays visible

### Fixed
- CIDR target validation
- Security Intel risk level (HIGH / MED badges and sorting)
- SAFE / ADV toggle hidden behind the right panel

### Security
- Nmap flags are whitelisted in the main process; `--script` accepts names only, not file paths
- IPC accepted only from the app window; navigation, new windows and permission requests blocked
- PDF reports rendered with JavaScript disabled and a strict CSP; scan data is HTML-escaped

## 1.0.0

- Initial release: visual Nmap command builder, live scan output, presets, cheatsheet, post-scan panels and exports (TXT / JSON / CSV)

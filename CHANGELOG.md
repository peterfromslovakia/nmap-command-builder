# Changelog

## 1.4.0 — 2026-11-21

### New
- **Professional vulnerability report in English or Slovak** — before exporting a PDF / Markdown report you choose the language and fill in who performed the test, organisation, client / system owner and authorisation reference (remembered for next time, optional). The report now has a confidentiality notice, an overall risk rating with an executive summary, a findings overview table, a scope & limitations section and page numbers with the tester's name in the PDF footer. All remediation steps and risk notes are translated
- **Update check** — on start (at most every 12 hours) the app checks GitHub for a newer version and offers the installer for your system (macOS Apple Silicon / Intel, Windows, Linux). *Help → Check for Updates…* checks on demand. The check only reads the public releases page, can be turned off, and the app never installs anything by itself
- **macOS Intel build** — releases now include `-x64.dmg` for Intel Macs next to `-arm64.dmg` for Apple Silicon

## 1.3.0 — 2026-11-21

### New
- **My presets** — save the current flags (optionally with the target) under your own name in the PRESETS tab and load them with one click. Stored only on this computer; saving under an existing name overwrites it
- **Keyboard shortcuts** — ⌘↵ / Ctrl+Enter run scan, ⌘. / Ctrl+. stop scan, ⌘F search flags, ⌘⇧C copy command, ⌘1–5 switch tabs (shown in the footer on wide windows)
- **Scan comparison in reports** — PDF and Markdown reports include "Changes since previous scan" for the baseline selected in the app
- **Application menu** — Edit (copy / paste), View (zoom, full screen), Help with links to the Nmap reference guide, NSE documentation, updates and issue reporting; About panel with version
- **Window size and position are remembered**; a window left on a disconnected monitor reopens on the main screen

### Improved
- Checkboxes use the theme colour
- CI runs ESLint (`npm run lint`, no warnings allowed)

### Maintenance
- Added the `LICENSE` file (MIT) and the `license` field in `package.json`
- Test files are no longer packaged into the app
- `.gitignore` covers test coverage, caches, logs, `.env.*` and editor files

## 1.2.0 — 2026-11-21

### New
- **Changes since previous scan** — after each scan the results are compared with the previous scan of the same target: new and disappeared hosts, newly opened and closed ports, version changes, new and fixed vulnerabilities. Any older scan can be picked as the baseline. Results (hosts, ports, findings — not the raw output) are stored locally in the app, max. 30 scans; "forget saved scans" deletes them.
- **Root notice** — when the app runs without root, a notice lists the selected flags that need root and what Nmap will do (stop or ignore the option), with tips for unprivileged alternatives. The command itself is never changed.
- **Adaptive UI scale** — the whole interface scales with the window size, from small laptop screens (1100×700) up to 1440p and 4K monitors

### Improved
- Result panels share one scroll area (no nested scrollbars); the terminal is taller on tall screens

### Fixed
- **macOS: "app is damaged and can't be opened"** — the app is now ad-hoc signed during the build
- `-A` is no longer marked as requiring root — it runs without root, only OS detection and traceroute are skipped (verified with Nmap 7.99)
- `--traceroute`, `-PU` and `--badsum` are now marked as requiring root

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

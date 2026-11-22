# Changelog

## 1.12.0 — 2026-11-22

### New
- **Port state accuracy in scan diff (F-001)** — `open → filtered` is no longer misclassified as "closed". The diff now reports three distinct categories: `filteredPorts` (port reached `filtered`/`closed|filtered`), `notTestedPorts` (different port range — port was not tested in the new scan), and `closedPorts` (confirmed closed). Both UI and Markdown/HTML report now show FILTERED PORTS and NOT TESTED PORTS sections
- **Confidence badges on findings (F-003)** — each finding now carries a `verificationStatus` field: `CONFIRMED` (live `State: VULNERABLE`), `LIKELY` (nmap said `State: LIKELY VULNERABLE`), `VERSION_MATCH` (vulners — based on version matching, not live exploit), `DETECTED` (misconfiguration / risky port). `LIKELY` and `VER` badges are shown next to severity in the UI
- **NSE error diagnostics (F-004)** — script errors (`| ERROR:` / `| NSE:` lines) are now captured by `parseNseErrors()` and shown in the Findings panel below the findings list, attributed to the script and port where they occurred
- **Bundled nmap data files (F-002)** — NSE scripts (`scripts/`), `nselib/`, `nmap-services`, `nmap-os-db`, `nmap-service-probes` and other nmap data files are now bundled alongside the binary in the installer. `NMAPDIR` is set at startup so nmap finds its data directory even on systems where nmap is not installed separately. Increases installer size by ~23 MB

### Fixed
- Lint: removed unused `RE_VULNERABLE` constant from `findings.js`

## 1.11.1 — 2026-11-22

### Security
- **`--script-args` validation relaxed to allow file paths** — the previous regex blocked legitimate NSE arguments that include file paths (e.g. `brute.db=/usr/share/wordlists/rockyou.txt`) and user-agent strings (`http.useragent=Mozilla/5.0`). The validator now allows `/` in script-arg values; shell injection characters (`;`, `&`, `|`, `\`, quotes etc.) remain blocked by the existing DANGEROUS check that runs after validation, since `spawn()` is always called without `shell: true`
- **`--script-args` validated in main process** — the nmap argument whitelist now validates `--script-args` values; previously only `--script` names were validated

### Fixed
- **UI shows "CRASHED" badge instead of "KILLED" when nmap crashes** — a scan terminated by SIGSEGV, SIGABRT or any unexpected signal now shows a "CRASHED" status badge in the UI, not "KILLED". Previously only the scan history entry was correct; now the UI badge matches. Uses the new `userKill` flag from the main process to reliably distinguish user-initiated stops from OS or crash signals
- **Port range changes tracked in diff** — when two scans used different port specs (e.g. `-p-` vs `-p 80,443`), the comparison now sets `portRangeDiffers: true` and shows the method warning in the report, preventing false claims about "closed ports" that were simply not tested in the new scan
- **Report: method-warning banner in comparison section** — when two scans differ in methodology (e.g. one was discovery-only, the other scanned ports), the PDF/Markdown report now shows an explicit warning in the "Changes" section explaining why port and vulnerability changes are not shown

## 1.11.0 — 2026-11-22

### New
- **Bundled nmap — no installation required** — nmap is included directly in the installer (.dmg / .exe / .AppImage). macOS ships a universal binary (arm64 + x64), Linux the x64 binary, Windows nmap.exe together with the Npcap driver installer. Users install the app and can scan immediately — no separate nmap download needed. If Npcap is missing on Windows, a banner offers one-click installation
- **TOOLS tab** — four network tools with no additional software required:
  - **WHOIS** — who owns a public IP or domain (registrar, country, ASN, name servers); follows WHOIS server referrals automatically
  - **DNS Lookup** — query A, AAAA, MX, NS, TXT, CNAME, SOA or PTR records (or all at once) using the system resolver
  - **SSL Certificate** — connect to any host/port and inspect the certificate: subject, issuer, validity, SANs, SHA-256 fingerprint, days remaining; expired and soon-to-expire certificates highlighted
  - **IP Information** — geolocation and ISP details for any public IP via ipinfo.io (free, no registration, no API key)
- Keyboard shortcut **⌘6 / Ctrl+6** switches to the TOOLS tab

### Fixed
- **Scan diff: false "closed ports" after discovery scan** — comparing a previous full scan (`-sV`) against a discovery-only scan (`-sn`) no longer marks all previously open ports as "closed". Ports that were simply not tested are skipped; only genuine methodology-compatible comparisons are shown
- **Scan diff: false "fixed vulnerabilities" after methodology change** — findings are marked as resolved only when both scans ran the same type of scripts; a port-only scan cannot "fix" vulnerabilities found by vuln scripts
- **Report risk: "NOT ASSESSED" for discovery scans** — a `-sn` ping scan now shows "Risk: NOT ASSESSED" in reports instead of "Risk: NONE". The difference matters: *none* means "tested and found nothing", *not assessed* means "no vulnerability testing was performed"
- **Scan history: crash vs kill** — a scan terminated by a crash signal (SIGSEGV, SIGABRT etc.) is now recorded with status `crashed` instead of `killed` in the scan history

## 1.9.0 — 2026-11-21

### New
- **Custom device labels** — assign your own name to any device (e.g. *My NAS*, *Work PC*). The label is tied to the MAC address, so it stays correct even when the IP changes. Labels are shown in the device list (click ✏ to edit), network map, PDF/Markdown reports, and CSV export. Stored locally on this computer

### Improved (tested on a real home network)
- **Better device recognition** — the device name now wins over port guesses (a MacBook with AirPlay is no longer a camera); names of UniFi gateways / switches / access points, EZVIZ / Hikvision / Reolink cameras, set-top boxes (Antik, STB), internet radios, EV chargers (Wallbox, Zappi), Shelly / Tasmota / smart-home devices, TVs and phones are recognised; UPnP alone no longer means "router"
- **Device type from the MAC vendor** — cameras (Ezviz, Hikvision, Dahua, Reolink, Axis…), internet radios and audio (Frontier Silicon, Teufel, Bose…), smart home (Netatmo, tado, Nuki, Philips Hue); private (randomised) phone / laptop MACs are shown as such, never with a guessed vendor
- **New device type: VoIP / IP phone** (Mitel, Yealink, Polycom, Snom, Grandstream, Fanvil, Gigaset, SIP)
- **Your own computer** gets the right type even without a host name
- **MAC addresses on macOS** — new macOS versions hide the neighbour table from apps; when no MAC addresses are available, the device list offers *🔒 FIND MAC ADDRESSES (administrator)* (a quick ARP scan as administrator, which also reports vendors and finds sleeping phones that ignore normal discovery). The macOS app now declares Local Network access
- Quick network scan shows a realistic time (~1–2 min for a /24)

## 1.8.0 — 2026-11-21

### New
- **Run as administrator without Terminal** — when a scan needs root (`-sS`, `-O`, `-sU`…), *🔒 RUN AS ADMINISTRATOR* runs the same command with administrator rights. macOS shows the system password dialog, Linux a graphical password / polkit dialog; the app never sees the password. Administrator runs refuse options that read or write files (`-oN/-oX/-oG`, `-iL`, script files, paths in script arguments). Verified on macOS with the real password dialog
- **Help → Open Data Folder** and **Help → Delete All Saved Data…** (saved scans, presets, report details, monitoring, vulnerability cache, settings; after confirmation). README lists where the data lives on each system

### Fixed
- **Large networks: no devices lost** — the terminal shows only the last part of very long output, but the device list, network map, findings and reports now use the complete scan output (before, on networks with thousands of devices the first devices could silently disappear)
- **Very long scan output in reports** — the raw-output appendix is shortened to its beginning and end (max. 2 MB) with a clear note, so the PDF always fits

### Tests
- Stress and edge cases: 3 000 devices, IPv6 hosts, empty / interrupted scans, Windows line endings, hostile service banners (HTML is escaped in reports)


## 1.7.0 — 2026-11-21

### New
- **Network map in reports** — PDF and Markdown reports from a network scan include *Appendix A — network map*: router, devices grouped by type, coloured by risk, with finding numbers (F-01…), CISA KEV marks and the scanning computer marked. The raw scanner output is now *Appendix B*
- **One frame per scanned range** in the network map — a single office network such as `10.0.0.0/22` (10.0.0.1 – 10.0.3.254) stays one network; several ranges scanned together get separate frames

### Improved
- **Whole office network is pre-filled** — networks up to /22 (1022 addresses, e.g. behind Kerio Control or FortiGate) are suggested whole; before only the /24 around your own address was offered
- **Kerio Control** is recognised as a firewall (admin port 4081 or its web server banner)
- The map and report show the gateway's real type (e.g. *Firewall* instead of *Router*)

## 1.6.0 — 2026-11-21

### New
- **Export / import of my presets** — share your presets with colleagues or back them up as a JSON file; imported presets are checked the same way as saved ones (unknown flags and invalid values are dropped, the same name replaces the existing preset)
- **Network map** — after a network scan: Internet → router (the computer's real default gateway) → devices grouped by type and coloured by risk (vulnerabilities, risky open ports), actively exploited devices marked, your own computer marked, filter for devices at risk, details and *SCAN ›* on click. Replaces the old simple host list
- **Automatic PDF reports from monitoring** — choose a folder once and a full report is saved after the first run and whenever new ports, devices or vulnerabilities appear

### Fixed
- Report table of contents showed "0." instead of "10." for the appendix

## 1.5.0 — 2026-11-21

### New
- **Scan network with one button** — *⌖ SCAN NETWORK* finds all active devices in the detected network (or the range you enter), *quick* or *detailed*. The new **Network devices** table shows the device type (router, firewall, printer, NAS, camera, Windows / Apple / Linux computer, phone, TV, IoT, access point), IP, name, OS, MAC address and vendor (from the system ARP table, so it works without root; randomised phone MACs are marked), open ports and latency, with filter, sort, CSV export and one-click *SCAN ›* per device
- **Live vulnerability intelligence without registration** — CVEs from the scan are checked against CISA KEV (actively exploited, ransomware use), FIRST EPSS (exploit probability) and NIST NVD (CVSS vector, CWE, description). Actively exploited findings are marked, raised to at least High and listed first. Only CVE numbers are sent; results are cached for offline use; can be turned off
- **Penetration-test style report** — cover page, document control, contents, executive summary with priority actions, scope & methodology from the actual command, risk rating with remediation timeframes, findings F-01… with CVSS / EPSS / CWE / KEV, impact and NIST description, asset inventory, sign-off table; English and Slovak
- **Slovak interface** — the whole app (panels, flags, presets, scripts, cheatsheet, ethics page, menu, dialogs, notifications) in English or Slovak, switch in the header
- **Monitoring** — repeat a scan every 15 min / 1 h / 6 h / 24 h and get a system notification about new devices, open ports or vulnerabilities

### Improved
- Report dialog starts in the interface language; scan date in reports is the time of the scan, not of the export
- Scan buttons adapt to narrow windows
- Two scans can no longer be started at the same time
- Ethics page: correct Slovak law reference (§ 247 Criminal Code)

### Removed
- The old *Host Discovery* panel (replaced by *Network devices*)

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

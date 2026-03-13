# Nmap Command Builder

A cyber-terminal desktop application for building, running, and analysing Nmap scans — with zero command-line experience required.

Built with **Electron 32** + **React 18**. Runs on macOS and Linux (Kali / Debian / Ubuntu).

---

## Features

### Command Builder
- Visual flag selector organised into collapsible categories (Target, Scan Type, Timing, Output, Evasion, and more)
- Live command preview — see the exact `nmap` string update as you select flags
- Safe / Advanced mode toggle — evasion and spoofing flags are hidden in Safe mode
- 12 built-in scan presets (Quick Scan, Full Port, Stealth SYN, UDP, Vuln Scan, and more)
- Searchable cheatsheet with Nmap reference data

### Scan Execution
- Runs nmap via `child_process.spawn` — no shell injection, no `exec`
- Live streaming terminal output with colour-coded line classification
- Kill button (SIGTERM) to stop long-running scans mid-flight
- Export results as `.txt`, `.json`, or `.csv`
- Scan history (last 10 runs) with one-click target reload

### Post-Scan Intelligence
- **Open Ports Panel** — table of open ports with per-row risk colouring (HIGH / MED / SAFE) and expandable follow-up action menus
- **Host Info Panel** — single-host summary: IP, hostname, MAC address, vendor, and latency
- **Host Discovery Panel** — grid of discovered hosts for subnet/CIDR scans
- **Network Map** — visual node graph of discovered hosts, automatically typed as router, gateway, server, workstation, or host
- **Security Intel Panel** — collapsible per-port risk notes, security hints, and NSE script suggestions; sorted HIGH → MEDIUM → SAFE
- **Follow-Up Scans Panel** — curated follow-up Nmap commands for each detected service; copy to clipboard or load directly into the builder

### Safety & Awareness
- `⚠ ROOT` badge when the selected scan type requires elevated privileges
- `⚠ IDS/IPS` badge when evasion, spoofing, or paranoid-timing flags are active
- Built-in **Ethics tab** with legal notice, root-required scan list, and responsible-use checklist

---

## Requirements

| Requirement | Version |
|---|---|
| Node.js | 18 or 20 (LTS recommended) |
| nmap | any recent version (`apt install nmap` / `brew install nmap`) |
| OS | macOS 12+ · Linux (Kali, Debian, Ubuntu) |

---

## Getting Started

```bash
# 1. Clone
git clone https://github.com/your-username/nmap-command-builder.git
cd nmap-command-builder

# 2. Install dependencies
npm install

# 3. Run in development mode
npm run dev
```

`npm run dev` starts the React dev server on port 3000 and opens Electron automatically.

### Production build

```bash
npm run build        # compile React
npm run electron     # launch Electron against the build
```

---

## Project Structure

```
├── electron/
│   ├── main.js          — BrowserWindow, IPC handlers, nmap spawn
│   └── preload.js       — contextBridge API (checkNmap / runScan / killScan / exportResult)
├── public/
│   └── index.html
├── src/
│   ├── App.js / App.css — root layout and all component styles
│   ├── index.js / index.css
│   ├── data/
│   │   ├── flags.js     — FLAG_CATEGORIES and FLAG_MAP
│   │   ├── presets.js   — 12 preset scan configs
│   │   ├── cheatsheet.js
│   │   ├── portRisk.js  — port → HIGH / MEDIUM / SAFE classification
│   │   └── portIntel.js — port intelligence (hints, NSE scripts, follow-up commands)
│   ├── utils/
│   │   ├── commandBuilder.js — buildCommand, parseScanSummary
│   │   └── validator.js
│   └── components/
│       ├── CommandPreview.jsx
│       ├── BuilderTab.jsx
│       ├── CheatsheetTab.jsx
│       ├── PresetsTab.jsx
│       ├── EthicsTab.jsx
│       ├── TerminalOutput.jsx
│       ├── ScanHistory.jsx
│       ├── PortsPanel.jsx
│       ├── HostInfoPanel.jsx
│       ├── HostDiscoveryPanel.jsx
│       ├── NetworkMap.jsx
│       ├── IntelPanel.jsx
│       └── FollowUpPanel.jsx
└── assets/
    ├── icon.png         — 512 × 512 application icon
    ├── icon.icns        — macOS icon bundle
    └── icon.ico         — Windows icon
```

---

## Security Model

- `contextIsolation: true`, `nodeIntegration: false` — renderer process has no Node.js access
- All nmap execution goes through `ipcMain` in the main process
- Arguments are validated with `validateTarget` and `sanitizeArg` before spawning
- `child_process.spawn` (not `exec`) — no shell, no injection surface

---

## Legal Notice

**Only scan networks and systems you own or have explicit written authorisation to test.**

Unauthorised port scanning may be illegal in your jurisdiction. The authors assume no liability for misuse. This tool is intended for network administrators, penetration testers with proper authorisation, and security researchers.

*SK: Skenovanie sietí bez povolenia je v SR trestným činom podľa § 247 Trestného zákona.*

---

## Author

**Peter Obala** — Use responsibly & ethically.

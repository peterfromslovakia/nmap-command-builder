# Nmap Command Builder

![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)
![Nmap](https://img.shields.io/badge/tool-nmap-red)
![Electron](https://img.shields.io/badge/built%20with-Electron-47848F)

A desktop cybersecurity tool for building, executing, and analysing **Nmap scans** through a graphical interface — no command-line experience required.

Built with **Electron + React** and designed for system administrators, security researchers, and students learning network reconnaissance.

---

## Screenshot

![Nmap Command Builder](docs/images/nmap_screenshot.png)

---

## Features

### Command Builder

- Visual flag selector organised into collapsible categories
- Live command preview — see the exact `nmap` command update instantly
- Safe / Advanced mode toggle
- 12 built-in scan presets
- Searchable Nmap cheatsheet

### Scan Execution

- Runs Nmap via `child_process.spawn`
- Live streaming terminal output
- Kill button to stop long scans
- Export results as `.txt`, `.json`, or `.csv`
- Scan history with quick reload

### Post-Scan Intelligence

- **Open Ports Panel** with risk classification
- **Host Info Panel** (IP, hostname, MAC, vendor)
- **Host Discovery Panel**
- **Network Map visualisation**
- **Security Intel Panel**
- **Follow-Up Scan suggestions**

### Safety & Awareness

- ⚠ ROOT badge for scans requiring elevated privileges
- ⚠ IDS/IPS warning when evasion techniques are used
- Built-in Ethics tab with legal notice and responsible use checklist

---

## Why this project exists

Many powerful cybersecurity tools require deep command-line knowledge.

This project aims to make **Nmap accessible through a graphical interface while still exposing the real commands being executed**.

It helps:

- system administrators
- cybersecurity students
- penetration testers
- network engineers

---

## Requirements

| Requirement | Version |
|---|---|
| Node.js | 18 or 20 |
| Nmap | any recent version |
| OS | macOS · Linux |

Install Nmap if needed:

Install Nmap if needed:

```bash
brew install nmap
```

or

```bash
sudo apt install nmap
```

---

## Getting Started

Clone repository:

```bash
git clone https://github.com/peterfromslovakia/nmap-command-builder.git
cd nmap-command-builder
```

Install dependencies:

```bash
npm install
```

Run development mode:

```bash
npm run dev
```

---

## Production build

```bash
npm run build
npm run electron
```
---

## Security Model

- contextIsolation enabled
- nodeIntegration disabled
- Nmap execution handled only in Electron main process
- arguments validated before execution
- spawn used instead of exec

---

## Responsible Use

Only scan networks and systems **you own or have explicit authorisation to test**.

Unauthorised port scanning may be illegal in your jurisdiction.

SK:  
Skenovanie sietí bez povolenia je v SR trestným činom podľa § 247 Trestného zákona.

---

## Author

**Peter Obala**

Cybersecurity enthusiast · Network administrator

---

## License

MIT License

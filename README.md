# Nmap Command Builder

![Build](https://github.com/peterfromslovakia/nmap-command-builder/actions/workflows/build.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey)
![Nmap](https://img.shields.io/badge/tool-nmap-red)
![Electron](https://img.shields.io/badge/built%20with-Electron-47848F)
![Last commit](https://img.shields.io/github/last-commit/peterfromslovakia/nmap-command-builder)
[![Release](https://img.shields.io/github/v/release/peterfromslovakia/nmap-command-builder)](https://github.com/peterfromslovakia/nmap-command-builder/releases)
[![Downloads](https://img.shields.io/github/downloads/peterfromslovakia/nmap-command-builder/total)](https://github.com/peterfromslovakia/nmap-command-builder/releases)

[English](#english) · [Slovensky](#slovensky)

---

<a name="english"></a>
# English

A desktop cybersecurity tool for building, executing, and analysing **Nmap scans** through a graphical interface — no command-line experience required. Interface in **English and Slovak**.

Built with **Electron + React** for system administrators, cybersecurity students, and network engineers.

---

## Screenshot

![Nmap Command Builder](docs/images/nmap_screenshot.png)

---

## What is installed automatically

**Everything is bundled inside the installer — no separate software download is required.**

| Platform | What the installer contains |
|---|---|
| macOS (Apple Silicon + Intel) | nmap universal binary (arm64 + x64 in one file, works on all Macs) |
| Linux | nmap x64 binary |
| Windows | nmap.exe + **Npcap installer** |

### Windows — Npcap

Npcap is the Windows packet-capture driver that nmap needs for privileged scans (SYN scan `-sS`, OS detection `-O`, UDP scan `-sU`). The Npcap installer is bundled inside the app:

- For basic scans you do not need Npcap at all
- When you first run a privileged scan, the app shows a banner: **Install Npcap**
- Clicking the button runs the bundled Npcap installer — Windows asks for administrator confirmation once (this is a kernel driver, so Windows always requires this)
- After that, all scan types work without restarting the app

The Windows app installer itself also runs as administrator (`perMachine` install) so it is available for all user accounts.

---

## Features

### Scan network with one button

- **⌖ SCAN NETWORK** finds all active devices in your network — *quick* (~1–2 min for a /24) or *detailed* (open ports and services)
- **Network devices** table: device type, IP, hostname, OS, MAC address and vendor (without root, from the ARP table), open ports and latency — filter, sort, CSV export and **SCAN ›** per device
- **Network map**: Internet → router → devices grouped by type, coloured by risk; CISA KEV marks, your computer marked *YOU*
- Works without root (TCP connect ping)

### Live vulnerability intelligence (no registration, no API key)

- Every CVE is checked against **CISA KEV** (exploited in the wild), **FIRST EPSS** (exploitation probability) and **NIST NVD** (CVSS, CWE, description)
- Only CVE numbers are sent; results are cached for offline use; can be turned off

### TOOLS tab — network tools, no installation needed

Four built-in tools that work straight away, no extra software:

| Tool | What it does |
|---|---|
| **WHOIS** | Who owns a domain or IP address — registrar, country, ASN, name servers; follows referral servers automatically |
| **DNS Lookup** | Query A, AAAA, MX, NS, TXT, CNAME, SOA, PTR records — or all types at once |
| **SSL Certificate** | Inspect the certificate of any host: subject, issuer, validity dates, SANs, SHA-256 fingerprint, days remaining; expired certificates highlighted |
| **IP Information** | Geolocation and ISP details for any public IP via ipinfo.io (free, no registration, no API key) |

### Reports

- **Penetration-test style PDF/Markdown** in English or Slovak: cover page, executive summary, findings F-01… with CVSS/EPSS/KEV/CWE, network map appendix, remediation steps, sign-off table
- **Monitoring**: repeat a scan every 15 min / 1 h / 6 h / 24 h with automatic PDF report on change

### Command builder

- Visual flag selector with 23 built-in presets labelled **LOW / NOISY / INTRUSIVE**
- My presets: save and share your own flag combinations
- Searchable cheatsheet, NSE script library (71 curated scripts)

---

## Requirements

| | |
|---|---|
| OS | macOS 11+ · Windows 10+ · Linux (x64) |
| Node.js | 18+ — only when running from source |

No other software required when using the prebuilt installer.

---

## Installation

### Option 1 — Prebuilt installer (recommended)

Download from **[Releases](https://github.com/peterfromslovakia/nmap-command-builder/releases)**:

| Platform | File |
|---|---|
| macOS Apple Silicon (M1–M5) | `…-arm64.dmg` |
| macOS Intel | `…-x64.dmg` |
| Windows | `…Setup-….exe` |
| Linux | `….AppImage` |

The app checks for updates on start (at most every 12 hours) and shows a banner with the right download for your system.

#### macOS — first launch

The app is not signed with a paid Apple Developer ID, so macOS blocks it on first launch:

1. Open the `.dmg` and drag **Nmap Command Builder** to **Applications**.
2. Open the app — macOS shows *"cannot be opened because Apple cannot check it for malicious software"*. Click **Done**.
3. Open **System Settings → Privacy & Security**, scroll down and click **Open Anyway**, then confirm.

Or from Terminal:

    xattr -cr "/Applications/Nmap Command Builder.app"

### Option 2 — Run from source

    git clone https://github.com/peterfromslovakia/nmap-command-builder.git
    cd nmap-command-builder
    npm install
    npm run dev

Nmap must be on PATH when running from source (`brew install nmap` / `sudo apt install nmap`).

---

## Keyboard shortcuts

| macOS | Windows / Linux | Action |
|---|---|---|
| ⌘ ↵ | Ctrl + Enter | Run scan |
| ⌘ . | Ctrl + . | Stop scan |
| ⌘ F | Ctrl + F | Search flags |
| ⌘ ⇧ C | Ctrl + Shift + C | Copy command |
| ⌘ 1 – 6 | Ctrl + 1 – 6 | Switch tab (Builder, Cheatsheet, Presets, Scripts, Ethics, Tools) |

---

## Root privileges

Some scan techniques require root / administrator rights (`-sS`, `-O`, `-sU`, …). The app never modifies the command — instead it shows which flags need root and offers **🔒 RUN AS ADMINISTRATOR** (macOS: system password dialog, Linux: polkit/zenity). On Windows, Npcap handles raw packet access so the app itself does not need to run as administrator.

---

## Where data is stored

| System | Folder |
|---|---|
| macOS | `~/Library/Application Support/Nmap Command Builder` |
| Windows | `%APPDATA%\Nmap Command Builder` |
| Linux | `~/.config/Nmap Command Builder` |

IP addresses, host names and scan output never leave your computer.

---

## Security model

- `contextIsolation` enabled, `nodeIntegration` disabled, renderer sandbox on
- Nmap runs only from the main process; flags checked against a whitelist; `--script` accepts names only (not file paths); `--script-args` values validated against an allowed pattern — shell injection characters always blocked
- IPC accepted only from the app window; navigation and new windows blocked
- PDF reports rendered with JavaScript disabled and a strict CSP; all scan data HTML-escaped

---

## Testing

    npm test          # 331 tests: validators, findings, reports, shortcuts, presets, scan diff, i18n
    npm run lint      # ESLint, no warnings allowed (also runs in CI)

---

## License

MIT — see [LICENSE](LICENSE).

---

<a name="slovensky"></a>
# Slovensky

Desktopový nástroj na kybernetickú bezpečnosť — vizuálne zostavovanie, spúšťanie a analýza **Nmap skenov** bez príkazového riadka. Rozhranie v **angličtine a slovenčine**.

---

## Čo sa nainštaluje automaticky

**Všetko je súčasťou inštalátora — žiadny ďalší softvér nie je potrebný.**

| Platforma | Čo inštalátor obsahuje |
|---|---|
| macOS (Apple Silicon + Intel) | nmap univerzálna binárka (arm64 + x64 v jednom súbore, funguje na všetkých Macoch) |
| Linux | nmap x64 binárka |
| Windows | nmap.exe + **inštalátor Npcap** |

### Windows — Npcap

Npcap je ovládač pre zachytávanie paketov vo Windowse, ktorý nmap potrebuje na privilegované skenovanie (SYN skenovanie `-sS`, detekcia OS `-O`, UDP skenovanie `-sU`). Inštalátor Npcap je priamo v aplikácii:

- Pre základné skeny Npcap vôbec nepotrebuješ
- Pri prvom spustení privilegovaného skenu sa zobrazí lišta: **Nainštalovať Npcap**
- Po kliknutí sa spustí bundlovaný inštalátor Npcap — Windows požiada o potvrdenie správcom raz (ide o ovládač jadra, Windows to vždy vyžaduje)
- Po inštalácii fungujú všetky typy skenov bez reštartu aplikácie

Samotný inštalátor Windows aplikácie tiež beží ako správca (`perMachine` inštalácia), takže je dostupný pre všetky používateľské účty.

---

## Funkcie

### Skenovanie siete jedným kliknutím

- **⌖ SKENOVAŤ SIEŤ** nájde všetky aktívne zariadenia — *rýchle* (~1–2 min pre /24) alebo *podrobné* (porty a služby)
- **Zoznam zariadení**: typ zariadenia, IP, meno, OS, MAC adresa a výrobca (bez rootu, z ARP tabuľky), otvorené porty a latenciu — filtrovanie, triedenie, export CSV a **SKENOVAŤ ›** pre každé zariadenie
- **Mapa siete**: Internet → router → zariadenia podľa typu, sfarbené podľa rizika; značky CISA KEV, tvoj počítač označený *TY*

### Spravodajstvo o zraniteľnostiach (bez registrácie, bez API kľúča)

- Každé CVE sa overuje voči **CISA KEV** (aktívne zneužívané), **FIRST EPSS** (pravdepodobnosť zneužitia) a **NIST NVD** (CVSS, CWE, popis)
- Odosielajú sa len čísla CVE; výsledky sa ukladajú do cache pre offline použitie; dá sa vypnúť

### Záložka NÁSTROJE — sieťové nástroje bez inštalácie

Štyri zabudované nástroje, ktoré fungujú ihneď, bez ďalšieho softvéru:

| Nástroj | Čo robí |
|---|---|
| **WHOIS** | Kto vlastní doménu alebo IP adresu — registrátor, krajina, ASN, nameservery; automaticky sleduje referral servery |
| **DNS vyhľadávanie** | Dotaz na záznamy A, AAAA, MX, NS, TXT, CNAME, SOA, PTR — alebo všetky naraz |
| **SSL certifikát** | Preskúmanie certifikátu ľubovoľného hostiteľa: subjekt, vydavateľ, platnosť, SANy, SHA-256 odtlačok, zostatok dní; vypršané certifikáty zvýraznené |
| **Informácie o IP** | Geolokácia a informácie o ISP pre ľubovoľnú verejnú IP cez ipinfo.io (zdarma, bez registrácie, bez API kľúča) |

### Správy

- **Penetračne-testový štýl PDF/Markdown** v angličtine alebo slovenčine: titulná strana, zhrnutie, zistenia F-01… s CVSS/EPSS/KEV/CWE, príloha s mapou siete, kroky nápravy, podpisový hárok
- **Monitoring**: opakovanie skenu každých 15 min / 1 h / 6 h / 24 h s automatickým PDF reportom pri zmene

### Zostavovač príkazov

- Vizuálny výber prepínačov s 23 vstavanými presetmi označenými **NÍZKE / HLUČNÉ / INVAZÍVNE**
- Vlastné presety: ulož a zdieľaj svoje kombinácie prepínačov
- Prehľadávateľný cheatsheet, knižnica NSE skriptov (71 skriptov)

---

## Požiadavky

| | |
|---|---|
| OS | macOS 11+ · Windows 10+ · Linux (x64) |
| Node.js | 18+ — len pri spustení zo zdrojového kódu |

Pri použití predpripraveného inštalátora nie je potrebný žiadny ďalší softvér.

---

## Inštalácia

### Možnosť 1 — Predpripravený inštalátor (odporúčané)

Stiahni z **[Releases](https://github.com/peterfromslovakia/nmap-command-builder/releases)**:

| Platforma | Súbor |
|---|---|
| macOS Apple Silicon (M1–M5) | `…-arm64.dmg` |
| macOS Intel | `…-x64.dmg` |
| Windows | `…Setup-….exe` |
| Linux | `….AppImage` |

Aplikácia kontroluje aktualizácie pri štarte (najčastejšie každých 12 hodín) a zobrazí lištu so správnym stiahnutím pre tvoj systém.

#### macOS — prvé spustenie

Aplikácia nie je podpísaná plateným Apple Developer ID, preto macOS pri prvom spustení zablokuje otvorenie:

1. Otvor `.dmg` a presuň **Nmap Command Builder** do **Aplikácie**.
2. Spusti aplikáciu — macOS zobrazí *"nemožno otvoriť, pretože Apple nemôže skontrolovať..."*. Klikni **Hotovo**.
3. Otvor **Systémové nastavenia → Súkromie a bezpečnosť**, posuň sa dolu a klikni **Otvoriť aj tak** vedľa *Nmap Command Builder*, potom potvrď.

Alebo z Terminálu:

    xattr -cr "/Applications/Nmap Command Builder.app"

### Možnosť 2 — Spustenie zo zdrojového kódu

    git clone https://github.com/peterfromslovakia/nmap-command-builder.git
    cd nmap-command-builder
    npm install
    npm run dev

Pri spustení zo zdrojového kódu musí byť nmap dostupný v PATH (`brew install nmap` / `sudo apt install nmap`).

---

## Klávesové skratky

| macOS | Windows / Linux | Akcia |
|---|---|---|
| ⌘ ↵ | Ctrl + Enter | Spustiť skenovanie |
| ⌘ . | Ctrl + . | Zastaviť skenovanie |
| ⌘ F | Ctrl + F | Hľadať prepínače |
| ⌘ ⇧ C | Ctrl + Shift + C | Kopírovať príkaz |
| ⌘ 1 – 6 | Ctrl + 1 – 6 | Prepínať záložky (Builder, Cheatsheet, Presety, Skripty, Etika, Nástroje) |

---

## Root oprávnenia

Niektoré techniky skenovania vyžadujú root/správcovské práva (`-sS`, `-O`, `-sU`, …). Aplikácia nikdy nemení príkaz — namiesto toho zobrazí, ktoré prepínače vyžadujú root, a ponúkne **🔒 SPUSTIŤ AKO SPRÁVCA** (macOS: systémový dialóg pre heslo, Linux: polkit/zenity). Na Windowse Npcap rieši prístup k surových paketom, takže samotná aplikácia nemusí bežať ako správca.

---

## Kde sa ukladajú dáta

| Systém | Priečinok |
|---|---|
| macOS | `~/Library/Application Support/Nmap Command Builder` |
| Windows | `%APPDATA%\Nmap Command Builder` |
| Linux | `~/.config/Nmap Command Builder` |

IP adresy, mená hostiteľov a výstupy skenov nikdy neopustia tvoj počítač.

---

## Zodpovedné používanie

Skenuj iba siete a systémy, ktoré **vlastníš alebo máš výslovné povolenie testovať**.

Neoprávnené skenovanie portov môže byť v mnohých jurisdikciách nezákonné. V Slovenskej republike je skenovanie sietí bez povolenia trestným činom podľa **§ 247 Trestného zákona**.

---

## Autor

**Peter Obala** — Cybersecurity enthusiast · Network administrator

GitHub: https://github.com/peterfromslovakia

---

## Licencia / License

MIT — pozri [LICENSE](LICENSE).

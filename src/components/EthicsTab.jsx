import React from 'react';
import { useLang } from '../i18n/ui';

// ─── Ethics / Legal Notice Tab (EN / SK) ──────────────────────────────────────
// Odseky s formatovanim (code, strong) su ako JSX pre kazdy jazyk zvlast.

const TEXT = {
  en: {
    title: 'ETHICS & LEGAL NOTICE',
    sub: 'Read before running any scan',
    authTitle: 'AUTHORIZATION REQUIRED',
    auth1: <>Only scan networks, systems, and hosts that you <strong>own</strong> or have <strong>explicit written permission</strong> to test.</>,
    auth2: 'Unauthorized port scanning is illegal in many jurisdictions and may violate computer crime laws including:',
    laws: ['Computer Fraud and Abuse Act (CFAA) — United States', 'Computer Misuse Act — United Kingdom', '§ 247 Criminal Code (unauthorised access to a computer system) — Slovak Republic', 'NIS2 Directive — European Union'],
    auth3: 'Scanning without authorization can result in criminal charges, civil liability, and immediate network bans.',
    rootTitle: 'ROOT-REQUIRED SCAN TYPES',
    root1: <>The following scan types require <code>root</code> or <code>sudo</code> privileges because they construct raw packets at the OS level:</>,
    rootFlags: [
      ['-sS', 'SYN Stealth Scan — sends raw TCP SYN packets'],
      ['-sF / -sX / -sN', 'FIN, Xmas, Null scans — raw packet manipulation'],
      ['-O', 'OS Detection — requires raw socket access'],
      ['-sI', 'Idle Scan — uses a zombie host (advanced, root)'],
      ['-D / -S', 'Decoy / Source IP spoofing — raw packet injection'],
    ],
    root2: <>Start the app with <code>sudo</code> to enable root-required features (see README → Root Privileges). The app shows a <span className="ethics-badge-root">⚠ REQUIRES ROOT</span> badge when active flags need elevated privileges and never changes your command on its own.</>,
    modeTitle: 'SAFE MODE vs ADVANCED MODE',
    safeItems: ['Standard scan types (-sT, -sU, -sV, -sC)', 'Timing templates (-T0 to -T5)', 'Port selection, host discovery', 'Output formats, verbosity', 'NSE scripts (safe category)'],
    safeNote: 'Recommended for most use cases. All flags are widely accepted in authorized penetration testing engagements.',
    advItems: ['Packet fragmentation (-f, --mtu)', 'Decoy scanning (-D)', 'Source IP spoofing (-S)', 'MAC address spoofing (--spoof-mac)', 'Proxy chains (--proxies)', 'Idle/zombie scan (-sI, -b)'],
    advNote: 'Evasion and spoofing flags. Use only in explicitly authorized red-team or research environments.',
    idsTitle: 'IDS / IPS DETECTION RISK',
    ids1: 'Many scan configurations will trigger Intrusion Detection and Prevention Systems. Be aware of detection likelihood:',
    idsRows: [
      ['high', 'HIGH', <>Aggressive scan <code>-A</code>, all-ports <code>-p-</code>, fast timing <code>-T4/-T5</code>, UDP scan <code>-sU</code></>],
      ['med', 'MED', <>SYN scan <code>-sS</code>, version detection <code>-sV</code>, default scripts <code>-sC</code></>],
      ['low', 'LOW', <>Slow timing <code>-T0/-T1</code>, ping scan <code>-sn</code>, fragmentation <code>-f</code></>],
    ],
    ids2: 'Even "stealthy" scans can be logged. Always assume your activity is monitored on any network you do not personally own.',
    checkTitle: 'ETHICAL USE CHECKLIST',
    checks: [
      'I have written authorization from the system/network owner',
      'I understand the scope of the authorized test',
      "I am complying with my organization's security policies",
      'I will document all scan activity and findings',
      'I will report vulnerabilities responsibly to the owner',
      'I will not use scan results to cause harm or unauthorized access',
    ],
    license: <>Nmap is free and open source software licensed under the Nmap Public Source License. This tool is an interface for Nmap and does not modify its behavior. Always consult the <strong>nmap.org</strong> documentation for full usage guidelines.</>,
    privacy: <>Online vulnerability data: only CVE numbers are sent to FIRST.org (EPSS) and NIST (NVD); the CISA KEV catalogue is downloaded as a whole. No IP addresses, host names or scan output leave this computer. No registration or API key is needed, and it can be turned off in the VULNERABILITIES panel.</>,
  },
  sk: {
    title: 'ETIKA A PRÁVNE UPOZORNENIE',
    sub: 'Prečítajte si pred spustením akéhokoľvek skenu',
    authTitle: 'POTREBNÉ POVOLENIE',
    auth1: <>Skenujte len siete, systémy a zariadenia, ktoré <strong>vlastníte</strong> alebo na ktorých testovanie máte <strong>výslovné písomné povolenie</strong>.</>,
    auth2: 'Neoprávnené skenovanie portov je v mnohých krajinách nezákonné a môže porušovať zákony o počítačovej kriminalite, napríklad:',
    laws: ['Computer Fraud and Abuse Act (CFAA) — USA', 'Computer Misuse Act — Spojené kráľovstvo', '§ 247 Trestného zákona (neoprávnený prístup do počítačového systému) — Slovenská republika', 'Smernica NIS2 — Európska únia'],
    auth3: 'Skenovanie bez povolenia môže viesť k trestnému stíhaniu, náhrade škody a okamžitému zablokovaniu v sieti.',
    rootTitle: 'SKENY VYŽADUJÚCE ROOT',
    root1: <>Nasledujúce typy skenov vyžadujú oprávnenia <code>root</code> alebo <code>sudo</code>, pretože vytvárajú pakety priamo na úrovni systému:</>,
    rootFlags: [
      ['-sS', 'SYN sken — posiela surové TCP SYN pakety'],
      ['-sF / -sX / -sN', 'FIN, Xmas, Null skeny — upravené pakety'],
      ['-O', 'Zistenie OS — vyžaduje prístup k surovým socketom'],
      ['-sI', 'Idle sken — cez „zombie“ zariadenie (pokročilé, root)'],
      ['-D / -S', 'Návnady / podvrhnutie zdrojovej IP — vkladanie paketov'],
    ],
    root2: <>Pre tieto funkcie spustite aplikáciu cez <code>sudo</code> (pozri README → Root Privileges). Aplikácia zobrazí odznak <span className="ethics-badge-root">⚠ VYŽADUJE ROOT</span>, keď zvolené prepínače potrebujú vyššie oprávnenia, a váš príkaz sama nikdy nezmení.</>,
    modeTitle: 'REŽIM SAFE vs ADV',
    safeItems: ['Bežné typy skenov (-sT, -sU, -sV, -sC)', 'Šablóny časovania (-T0 až -T5)', 'Výber portov, vyhľadanie zariadení', 'Formáty výstupu, podrobnosť výpisu', 'Skripty NSE (kategória safe)'],
    safeNote: 'Odporúčané pre väčšinu použití. Všetky prepínače sú bežne akceptované pri povolených penetračných testoch.',
    advItems: ['Fragmentácia paketov (-f, --mtu)', 'Sken s návnadami (-D)', 'Podvrhnutie zdrojovej IP (-S)', 'Podvrhnutie MAC adresy (--spoof-mac)', 'Reťaz proxy (--proxies)', 'Idle/zombie sken (-sI, -b)'],
    advNote: 'Prepínače na obchádzanie ochrany a podvrhovanie. Len vo výslovne povolených red-team alebo výskumných prostrediach.',
    idsTitle: 'RIZIKO ODHALENIA IDS / IPS',
    ids1: 'Mnohé nastavenia skenu spustia poplach v systémoch na detekciu a prevenciu prienikov. Pravdepodobnosť odhalenia:',
    idsRows: [
      ['high', 'VYSOKÁ', <>Agresívny sken <code>-A</code>, všetky porty <code>-p-</code>, rýchle časovanie <code>-T4/-T5</code>, UDP sken <code>-sU</code></>],
      ['med', 'STREDNÁ', <>SYN sken <code>-sS</code>, zistenie verzií <code>-sV</code>, predvolené skripty <code>-sC</code></>],
      ['low', 'NÍZKA', <>Pomalé časovanie <code>-T0/-T1</code>, ping sken <code>-sn</code>, fragmentácia <code>-f</code></>],
    ],
    ids2: 'Aj „nenápadné“ skeny sa môžu zaznamenať. V sieti, ktorú osobne nevlastníte, vždy počítajte s tým, že vašu činnosť niekto sleduje.',
    checkTitle: 'KONTROLNÝ ZOZNAM ETICKÉHO POUŽITIA',
    checks: [
      'Mám písomné povolenie od vlastníka systému / siete',
      'Rozumiem rozsahu povoleného testu',
      'Dodržiavam bezpečnostné pravidlá svojej organizácie',
      'Celú činnosť a zistenia budem dokumentovať',
      'Zraniteľnosti zodpovedne nahlásim vlastníkovi',
      'Výsledky nezneužijem na spôsobenie škody ani neoprávnený prístup',
    ],
    license: <>Nmap je bezplatný softvér s otvoreným kódom pod licenciou Nmap Public Source License. Táto aplikácia je rozhraním pre Nmap a nemení jeho správanie. Úplné pokyny nájdete v dokumentácii na <strong>nmap.org</strong>.</>,
    privacy: <>Online údaje o zraniteľnostiach: na FIRST.org (EPSS) a NIST (NVD) sa posielajú len čísla CVE; katalóg CISA KEV sa sťahuje celý. IP adresy, názvy zariadení ani výstup skenu tento počítač neopúšťajú. Nie je potrebná registrácia ani API kľúč a v paneli ZRANITEĽNOSTI sa to dá vypnúť.</>,
  },
};

export default function EthicsTab() {
  const { lang } = useLang();
  const T = TEXT[lang] || TEXT.en;
  return (
    <div className="ethics-tab">
      <div className="ethics-header">
        <span className="ethics-header__icon">⚖</span>
        <div>
          <div className="ethics-header__title">{T.title}</div>
          <div className="ethics-header__sub">{T.sub}</div>
        </div>
      </div>

      <div className="ethics-box ethics-box--danger">
        <div className="ethics-box__header">
          <span className="ethics-box__icon">⚠</span>
          <span className="ethics-box__title">{T.authTitle}</span>
        </div>
        <p className="ethics-box__text">{T.auth1}</p>
        <p className="ethics-box__text">{T.auth2}</p>
        <ul className="ethics-list">
          {T.laws.map((l) => <li key={l}>{l}</li>)}
        </ul>
        <p className="ethics-box__text ethics-box__text--dim">{T.auth3}</p>
      </div>

      <div className="ethics-box ethics-box--warn">
        <div className="ethics-box__header">
          <span className="ethics-box__icon">⚡</span>
          <span className="ethics-box__title">{T.rootTitle}</span>
        </div>
        <p className="ethics-box__text">{T.root1}</p>
        <div className="ethics-flag-list">
          {T.rootFlags.map(([flag, text]) => (
            <div key={flag} className="ethics-flag-row">
              <code className="ethics-flag">{flag}</code>
              <span>{text}</span>
            </div>
          ))}
        </div>
        <p className="ethics-box__text ethics-box__text--dim">{T.root2}</p>
      </div>

      <div className="ethics-box ethics-box--info">
        <div className="ethics-box__header">
          <span className="ethics-box__icon">🔒</span>
          <span className="ethics-box__title">{T.modeTitle}</span>
        </div>
        <div className="ethics-mode-compare">
          <div className="ethics-mode-block ethics-mode-block--safe">
            <div className="ethics-mode-label">SAFE</div>
            <ul className="ethics-list ethics-list--compact">
              {T.safeItems.map((x) => <li key={x}>{x}</li>)}
            </ul>
            <p className="ethics-mode-note">{T.safeNote}</p>
          </div>
          <div className="ethics-mode-block ethics-mode-block--adv">
            <div className="ethics-mode-label ethics-mode-label--adv">ADV</div>
            <ul className="ethics-list ethics-list--compact">
              {T.advItems.map((x) => <li key={x}>{x}</li>)}
            </ul>
            <p className="ethics-mode-note ethics-mode-note--adv">{T.advNote}</p>
          </div>
        </div>
      </div>

      <div className="ethics-box ethics-box--info">
        <div className="ethics-box__header">
          <span className="ethics-box__icon">👁</span>
          <span className="ethics-box__title">{T.idsTitle}</span>
        </div>
        <p className="ethics-box__text">{T.ids1}</p>
        <div className="ethics-detect-table">
          {T.idsRows.map(([cls, label, text]) => (
            <div key={cls} className="ethics-detect-row">
              <span className={`ethics-detect-risk ethics-detect-risk--${cls}`}>{label}</span>
              <span>{text}</span>
            </div>
          ))}
        </div>
        <p className="ethics-box__text ethics-box__text--dim">{T.ids2}</p>
      </div>

      <div className="ethics-box ethics-box--green">
        <div className="ethics-box__header">
          <span className="ethics-box__icon">✓</span>
          <span className="ethics-box__title">{T.checkTitle}</span>
        </div>
        <div className="ethics-checklist">
          {T.checks.map((c) => (
            <label key={c} className="ethics-check-item">
              <span className="ethics-check-mark">◇</span>
              <span>{c}</span>
            </label>
          ))}
        </div>
      </div>

      <div className="ethics-nmap-note">
        <span className="ethics-nmap-note__icon">ℹ</span>
        <span>{T.privacy}</span>
      </div>
      <div className="ethics-nmap-note">
        <span className="ethics-nmap-note__icon">ℹ</span>
        <span>{T.license}</span>
      </div>
    </div>
  );
}

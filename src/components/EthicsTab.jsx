import React from 'react';

// ─── Ethics / Legal Notice Tab ────────────────────────────────────────────────
export default function EthicsTab() {
  return (
    <div className="ethics-tab">

      {/* ── Title block ─────────────────────────────────────────────────────── */}
      <div className="ethics-header">
        <span className="ethics-header__icon">⚖</span>
        <div>
          <div className="ethics-header__title">ETHICS &amp; LEGAL NOTICE</div>
          <div className="ethics-header__sub">Read before running any scan</div>
        </div>
      </div>

      {/* ── 1: Legal authorization ──────────────────────────────────────────── */}
      <div className="ethics-box ethics-box--danger">
        <div className="ethics-box__header">
          <span className="ethics-box__icon">⚠</span>
          <span className="ethics-box__title">AUTHORIZATION REQUIRED</span>
        </div>
        <p className="ethics-box__text">
          Only scan networks, systems, and hosts that you <strong>own</strong> or
          have <strong>explicit written permission</strong> to test.
        </p>
        <p className="ethics-box__text">
          Unauthorized port scanning is illegal in many jurisdictions and may
          violate computer crime laws including:
        </p>
        <ul className="ethics-list">
          <li>Computer Fraud and Abuse Act (CFAA) — United States</li>
          <li>Computer Misuse Act — United Kingdom</li>
          <li>§ 207 Trestného zákona — Slovak Republic</li>
          <li>NIS2 Directive — European Union</li>
        </ul>
        <p className="ethics-box__text ethics-box__text--dim">
          Scanning without authorization can result in criminal charges, civil
          liability, and immediate network bans.
        </p>
      </div>

      {/* ── 2: Root-required scans ──────────────────────────────────────────── */}
      <div className="ethics-box ethics-box--warn">
        <div className="ethics-box__header">
          <span className="ethics-box__icon">⚡</span>
          <span className="ethics-box__title">ROOT-REQUIRED SCAN TYPES</span>
        </div>
        <p className="ethics-box__text">
          The following scan types require <code>root</code> or <code>sudo</code> privileges
          because they construct raw packets at the OS level:
        </p>
        <div className="ethics-flag-list">
          <div className="ethics-flag-row">
            <code className="ethics-flag">-sS</code>
            <span>SYN Stealth Scan — sends raw TCP SYN packets</span>
          </div>
          <div className="ethics-flag-row">
            <code className="ethics-flag">-sF / -sX / -sN</code>
            <span>FIN, Xmas, Null scans — raw packet manipulation</span>
          </div>
          <div className="ethics-flag-row">
            <code className="ethics-flag">-O</code>
            <span>OS Detection — requires raw socket access</span>
          </div>
          <div className="ethics-flag-row">
            <code className="ethics-flag">-sI</code>
            <span>Idle Scan — uses a zombie host (advanced, root)</span>
          </div>
          <div className="ethics-flag-row">
            <code className="ethics-flag">-D / -S</code>
            <span>Decoy / Source IP spoofing — raw packet injection</span>
          </div>
        </div>
        <p className="ethics-box__text ethics-box__text--dim">
          Run with <code>sudo -E npm run dev</code> to enable root-required features.
          The app displays a <span className="ethics-badge-root">⚠ REQUIRES ROOT</span> badge
          when active flags need elevated privileges.
        </p>
      </div>

      {/* ── 3: Safe vs Advanced mode ────────────────────────────────────────── */}
      <div className="ethics-box ethics-box--info">
        <div className="ethics-box__header">
          <span className="ethics-box__icon">🔒</span>
          <span className="ethics-box__title">SAFE MODE vs ADVANCED MODE</span>
        </div>
        <div className="ethics-mode-compare">
          <div className="ethics-mode-block ethics-mode-block--safe">
            <div className="ethics-mode-label">SAFE</div>
            <ul className="ethics-list ethics-list--compact">
              <li>Standard scan types (-sT, -sU, -sV, -sC)</li>
              <li>Timing templates (-T0 to -T5)</li>
              <li>Port selection, host discovery</li>
              <li>Output formats, verbosity</li>
              <li>NSE scripts (safe category)</li>
            </ul>
            <p className="ethics-mode-note">
              Recommended for most use cases. All flags are widely accepted in
              authorized penetration testing engagements.
            </p>
          </div>
          <div className="ethics-mode-block ethics-mode-block--adv">
            <div className="ethics-mode-label ethics-mode-label--adv">ADV</div>
            <ul className="ethics-list ethics-list--compact">
              <li>Packet fragmentation (-f, --mtu)</li>
              <li>Decoy scanning (-D)</li>
              <li>Source IP spoofing (-S)</li>
              <li>MAC address spoofing (--spoof-mac)</li>
              <li>Proxy chains (--proxies)</li>
              <li>Idle/zombie scan (-sI, -b)</li>
            </ul>
            <p className="ethics-mode-note ethics-mode-note--adv">
              Evasion and spoofing flags. Use only in explicitly authorized
              red-team or research environments.
            </p>
          </div>
        </div>
      </div>

      {/* ── 4: IDS/IPS detection ────────────────────────────────────────────── */}
      <div className="ethics-box ethics-box--info">
        <div className="ethics-box__header">
          <span className="ethics-box__icon">👁</span>
          <span className="ethics-box__title">IDS / IPS DETECTION RISK</span>
        </div>
        <p className="ethics-box__text">
          Many scan configurations will trigger Intrusion Detection and Prevention
          Systems. Be aware of detection likelihood:
        </p>
        <div className="ethics-detect-table">
          <div className="ethics-detect-row">
            <span className="ethics-detect-risk ethics-detect-risk--high">HIGH</span>
            <span>Aggressive scan <code>-A</code>, all-ports <code>-p-</code>, fast timing <code>-T4/-T5</code>, UDP scan <code>-sU</code></span>
          </div>
          <div className="ethics-detect-row">
            <span className="ethics-detect-risk ethics-detect-risk--med">MED</span>
            <span>SYN scan <code>-sS</code>, version detection <code>-sV</code>, default scripts <code>-sC</code></span>
          </div>
          <div className="ethics-detect-row">
            <span className="ethics-detect-risk ethics-detect-risk--low">LOW</span>
            <span>Slow timing <code>-T0/-T1</code>, ping scan <code>-sn</code>, fragmentation <code>-f</code></span>
          </div>
        </div>
        <p className="ethics-box__text ethics-box__text--dim">
          Even "stealthy" scans can be logged. Always assume your activity is
          monitored on any network you do not personally own.
        </p>
      </div>

      {/* ── 5: Ethical use checklist ────────────────────────────────────────── */}
      <div className="ethics-box ethics-box--green">
        <div className="ethics-box__header">
          <span className="ethics-box__icon">✓</span>
          <span className="ethics-box__title">ETHICAL USE CHECKLIST</span>
        </div>
        <div className="ethics-checklist">
          <label className="ethics-check-item">
            <span className="ethics-check-mark">◇</span>
            <span>I have written authorization from the system/network owner</span>
          </label>
          <label className="ethics-check-item">
            <span className="ethics-check-mark">◇</span>
            <span>I understand the scope of the authorized test</span>
          </label>
          <label className="ethics-check-item">
            <span className="ethics-check-mark">◇</span>
            <span>I am complying with my organization's security policies</span>
          </label>
          <label className="ethics-check-item">
            <span className="ethics-check-mark">◇</span>
            <span>I will document all scan activity and findings</span>
          </label>
          <label className="ethics-check-item">
            <span className="ethics-check-mark">◇</span>
            <span>I will report vulnerabilities responsibly to the owner</span>
          </label>
          <label className="ethics-check-item">
            <span className="ethics-check-mark">◇</span>
            <span>I will not use scan results to cause harm or unauthorized access</span>
          </label>
        </div>
      </div>

      {/* ── 6: Nmap license note ────────────────────────────────────────────── */}
      <div className="ethics-nmap-note">
        <span className="ethics-nmap-note__icon">ℹ</span>
        <span>
          Nmap is free and open source software licensed under the
          Nmap Public Source License. This tool is an interface for Nmap and does
          not modify its behavior. Always consult
          the <strong>nmap.org</strong> documentation for full usage guidelines.
        </span>
      </div>

    </div>
  );
}

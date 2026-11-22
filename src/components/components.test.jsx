import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { LangProvider } from '../i18n/ui';
import FindingsPanel from './FindingsPanel';
import DiffPanel from './DiffPanel';
import { makeSnapshot } from '../utils/scanDiff';

// FindingsPanel needs navigator.clipboard in tests
Object.defineProperty(navigator, 'clipboard', { value: { writeText: jest.fn() }, writable: true });

const wrap = (ui, lang = 'en') => render(<LangProvider initial={lang}>{ui}</LangProvider>);

// ── FindingsPanel helpers ────────────────────────────────────────────────────

const BASE_LINES = [{ text: `Nmap scan report for 192.168.1.5\nPORT   STATE SERVICE\n80/tcp open  http\n` }];

const makeFinding = (extra = {}) => ({
  id: 'http-vuln-test', title: 'Test vuln', severity: 'high',
  host: '192.168.1.5', port: '80', cvss: null, cves: [],
  evidence: 'State: VULNERABLE',
  verificationStatus: 'CONFIRMED',
  fix: [], refs: [],
  ...extra,
});

const basePanel = (extra = {}) => (
  <FindingsPanel
    lines={BASE_LINES}
    scanStatus="done"
    onLoadVulnScan={() => {}}
    onExport={() => {}}
    findings={[makeFinding()]}
    intel={{ enabled: false, loading: false, meta: null, nvdDone: 0, nvdTotal: 0 }}
    onToggleIntel={() => {}}
    {...extra}
  />
);

// ── FindingsPanel tests ──────────────────────────────────────────────────────

describe('FindingsPanel', () => {
  test('returns null when scanStatus is idle', () => {
    const { container } = wrap(basePanel({ scanStatus: 'idle', findings: [] }));
    expect(container.firstChild).toBeNull();
  });

  test('returns null when scanStatus is crashed', () => {
    const { container } = wrap(basePanel({ scanStatus: 'crashed', findings: [] }));
    expect(container.firstChild).toBeNull();
  });

  test('renders finding title for scanStatus done', () => {
    wrap(basePanel());
    expect(screen.getByText(/Test vuln/)).toBeInTheDocument();
  });

  test('LIKELY badge visible for verificationStatus LIKELY', () => {
    wrap(basePanel({ findings: [makeFinding({ verificationStatus: 'LIKELY' })] }));
    expect(screen.getByText('LIKELY')).toBeInTheDocument();
  });

  test('no LIKELY badge for CONFIRMED finding', () => {
    wrap(basePanel({ findings: [makeFinding({ verificationStatus: 'CONFIRMED' })] }));
    expect(screen.queryByText('LIKELY')).not.toBeInTheDocument();
  });

  test('VER badge visible for verificationStatus VERSION_MATCH', () => {
    wrap(basePanel({ findings: [makeFinding({ verificationStatus: 'VERSION_MATCH' })] }));
    expect(screen.getByText('VER')).toBeInTheDocument();
  });

  test('no VER badge for CONFIRMED finding', () => {
    wrap(basePanel({ findings: [makeFinding({ verificationStatus: 'CONFIRMED' })] }));
    expect(screen.queryByText('VER')).not.toBeInTheDocument();
  });

  test('NSE errors section shown when nseErrors prop is non-empty', () => {
    wrap(basePanel({ nseErrors: [{ host: '192.168.1.5', port: '80', script: 'http-enum', error: 'Script execution failed' }] }));
    expect(screen.getByText(/NSE ERRORS/)).toBeInTheDocument();
    expect(screen.getByText('http-enum')).toBeInTheDocument();
    expect(screen.getByText(/Script execution failed/)).toBeInTheDocument();
  });

  test('NSE errors section absent when nseErrors is empty', () => {
    wrap(basePanel({ nseErrors: [] }));
    expect(screen.queryByText(/NSE ERRORS/)).not.toBeInTheDocument();
  });

  test('LIKELY badge shows Slovak tooltip via LangProvider sk', () => {
    wrap(basePanel({ findings: [makeFinding({ verificationStatus: 'LIKELY' })] }), 'sk');
    const badge = screen.getByText('LIKELY');
    expect(badge).toHaveAttribute('title', expect.stringMatching(/Pravdepodobne/));
  });
});

// ── DiffPanel helpers ────────────────────────────────────────────────────────

const PREV_TEXT = `Nmap scan report for 192.168.1.5
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
`;

const CURR_TEXT_FILTERED = `Nmap scan report for 192.168.1.5
PORT    STATE    SERVICE
22/tcp  open     ssh
80/tcp  filtered http
`;

const CURR_TEXT_OPEN_ONLY = `Nmap scan report for 192.168.1.5
PORT    STATE SERVICE
22/tcp  open  ssh
`;

const mkSnap = (id, text, cmd = 'nmap -sV 192.168.1.5', extra = {}) =>
  makeSnapshot({ id, time: `2026-11-2${id}T10:00:00Z`, target: '192.168.1.5', command: cmd, text, ...extra });

const makeDiffPanel = (prev, curr) => {
  const snapshots = [prev, curr];
  return (
    <DiffPanel
      current={curr}
      snapshots={snapshots}
      baselineId={prev.id}
      onBaselineChange={() => {}}
      onClearSaved={() => {}}
    />
  );
};

// ── DiffPanel tests ──────────────────────────────────────────────────────────

describe('DiffPanel', () => {
  test('renders FILTERED PORTS section when filteredPorts non-empty', () => {
    const prev = mkSnap(1, PREV_TEXT);
    const curr = mkSnap(2, CURR_TEXT_FILTERED);
    wrap(makeDiffPanel(prev, curr));
    expect(screen.getByText(/FILTERED PORTS/i)).toBeInTheDocument();
    expect(screen.getByText(/80/)).toBeInTheDocument();
  });

  test('renders NOT TESTED PORTS section when scan uses --open flag', () => {
    const prev = mkSnap(1, PREV_TEXT);
    const curr = mkSnap(2, CURR_TEXT_OPEN_ONLY, 'nmap -sV --open 192.168.1.5');
    wrap(makeDiffPanel(prev, curr));
    expect(screen.getByText(/NOT TESTED PORTS/i)).toBeInTheDocument();
  });

  test('renders Slovak labels for FILTERED PORTS when lang=sk', () => {
    const prev = mkSnap(1, PREV_TEXT);
    const curr = mkSnap(2, CURR_TEXT_FILTERED);
    wrap(makeDiffPanel(prev, curr), 'sk');
    expect(screen.getByText(/FILTROVANÉ PORTY/i)).toBeInTheDocument();
  });

  test('renders Slovak labels for NOT TESTED PORTS when lang=sk', () => {
    const prev = mkSnap(1, PREV_TEXT);
    const curr = mkSnap(2, CURR_TEXT_OPEN_ONLY, 'nmap -sV --open 192.168.1.5');
    wrap(makeDiffPanel(prev, curr), 'sk');
    expect(screen.getByText(/NETESTOVANÉ PORTY/i)).toBeInTheDocument();
  });

  test('closed port goes to CLOSED PORTS (clean scan)', () => {
    const prev = mkSnap(1, PREV_TEXT);
    const curr = mkSnap(2, `Nmap scan report for 192.168.1.5\nPORT   STATE SERVICE\n22/tcp open  ssh\n`, 'nmap -sV 192.168.1.5', { exitCode: 0 });
    wrap(makeDiffPanel(prev, curr));
    expect(screen.getByText(/CLOSED PORTS/i)).toBeInTheDocument();
  });
});

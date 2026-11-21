import { parseFindings, SEVERITY_ORDER } from './findings';
import { getPortRisk } from '../data/portRisk';
import { getPortIntel } from '../data/portIntel';
import { getPortFixes } from '../data/remediation';

const RE_HOST = /^Nmap scan report for (.+)$/;
const RE_PORT = /^(\d+)\/(tcp|udp)\s+(open|open\|filtered)\s+(\S+)(?:\s+(.*))?$/;

/** Hosty a ich otvorene porty z vystupu nmapu. */
export function parseHosts(text) {
  const hosts = [];
  let cur = null;
  for (const raw of String(text || '').split('\n')) {
    const line = raw.replace(/\r$/, '');
    const h = line.match(RE_HOST);
    if (h) { cur = { host: h[1].trim(), ports: [] }; hosts.push(cur); continue; }
    const p = line.match(RE_PORT);
    if (p && cur) {
      cur.ports.push({
        port: p[1], proto: p[2], state: p[3], service: p[4], version: (p[5] || '').trim(),
        risk: getPortRisk(p[1]) || 'safe',
      });
    }
  }
  return hosts;
}

/**
 * Datovy model reportu — spolocny pre Markdown aj HTML/PDF.
 */
/**
 * Zmeny oproti predchadzajucemu skenu ako jednoduche textove riadky
 * (spolocne pre Markdown aj PDF). `diff` je vysledok diffScans().
 */
export function changeSections(diff) {
  if (!diff) return [];
  const port = (p) => `${p.port}/${p.proto} ${p.service}${p.version ? ` ${p.version}` : ''} — ${p.host}`;
  const finding = (f) => `[${String(f.severity).toUpperCase()}] ${f.title} — ${f.host}${f.port ? ` · ${f.port}` : ''}`;
  return [
    { title: 'New vulnerabilities', tone: 'bad', items: diff.newFindings.map(finding) },
    { title: 'New open ports', tone: 'bad', items: diff.openedPorts.map(port) },
    { title: 'New hosts', tone: 'bad', items: diff.newHosts.map((h) => `${h.host} (${h.ports.map((p) => p.port).join(', ') || 'no open ports'})`) },
    { title: 'Version changes', tone: 'info', items: diff.changedVersions.map((c) => `${c.port}/${c.proto} ${c.service}: ${c.from} → ${c.to} — ${c.host}`) },
    { title: 'Fixed vulnerabilities', tone: 'good', items: diff.resolvedFindings.map(finding) },
    { title: 'Closed ports', tone: 'good', items: diff.closedPorts.map(port) },
    { title: 'Hosts not found', tone: 'info', items: diff.goneHosts.map((h) => `${h.host} (down or filtered)`) },
  ].filter((sec) => sec.items.length > 0);
}

export function buildReportModel({ text, command, target, timestamp, nmapVersion, comparison }) {
  const hosts = parseHosts(text);
  const findings = parseFindings(text);

  // Odporucania pre rizikove porty (deduplikovane podla portu).
  const seen = new Set();
  const portAdvice = [];
  hosts.forEach((h) => h.ports.forEach((p) => {
    if (seen.has(p.port) || p.risk === 'safe') return;
    const fixes = getPortFixes(p.port);
    if (fixes.length === 0) return;
    seen.add(p.port);
    const intel = getPortIntel(p.port);
    portAdvice.push({
      port: p.port, risk: p.risk, label: intel?.label || p.service,
      note: intel?.risk || '', fixes,
      hosts: hosts.filter((x) => x.ports.some((q) => q.port === p.port)).map((x) => x.host),
    });
  }));
  portAdvice.sort((a, b) => (a.risk === 'high' ? 0 : 1) - (b.risk === 'high' ? 0 : 1));

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((f) => { counts[f.severity] += 1; });

  return {
    command, target, timestamp, nmapVersion: nmapVersion || '',
    hosts, findings, portAdvice, counts,
    // comparison: { baselineTime, baselineCommand, sameCommand, sections }
    comparison: comparison && comparison.diff ? {
      baselineTime: comparison.baselineTime,
      baselineCommand: comparison.baselineCommand,
      sameCommand: comparison.diff.sameCommand,
      sections: changeSections(comparison.diff),
    } : null,
    openPortCount: hosts.reduce((n, h) => n + h.ports.length, 0),
    raw: String(text || '').trim(),
  };
}

// ─── Markdown ─────────────────────────────────────────────────────────────────

const mdCell = (v) => String(v ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');

export function toMarkdown(m) {
  const out = [];
  out.push('# Nmap Scan Report', '');
  out.push(`- **Target:** \`${m.target}\``);
  out.push(`- **Command:** \`${m.command}\``);
  out.push(`- **Date:** ${m.timestamp}`);
  if (m.nmapVersion) out.push(`- **Nmap:** ${m.nmapVersion}`);
  out.push('', '## Summary', '');
  out.push(`- Hosts up: **${m.hosts.length}**`);
  out.push(`- Open ports: **${m.openPortCount}**`);
  out.push(`- Findings: **${m.findings.length}**` +
    (m.findings.length
      ? ` (critical ${m.counts.critical}, high ${m.counts.high}, medium ${m.counts.medium}, low ${m.counts.low})`
      : ''));

  if (m.comparison) {
    const cmp = m.comparison;
    out.push('', '## Changes Since Previous Scan', '');
    out.push(`Compared with the scan from ${cmp.baselineTime} (\`${cmp.baselineCommand}\`).`);
    if (!cmp.sameCommand) out.push('', '> Different command — some differences may come from different options.');
    if (cmp.sections.length === 0) out.push('', '_No changes._');
    cmp.sections.forEach((sec) => {
      out.push('', `**${sec.title}**`, '');
      sec.items.forEach((it) => out.push(`- ${mdCell(it)}`));
    });
  }

  out.push('', '## Vulnerabilities & Fixes', '');
  if (m.findings.length === 0) {
    out.push('_No known vulnerabilities were detected by the NSE scripts that ran. ' +
      'Run `nmap -sV --script vuln,vulners <target>` for a vulnerability check._');
  }
  m.findings.forEach((f, i) => {
    out.push(`### ${i + 1}. [${f.severity.toUpperCase()}] ${f.title}`, '');
    out.push(`- **Host:** ${f.host}${f.port ? ` — port ${f.port}` : ''}`);
    out.push(`- **Detected by:** \`${f.script}\``);
    if (f.evidence) out.push(`- **Evidence:** ${f.evidence}`);
    out.push('', '**How to fix:**', '');
    f.fix.forEach((s, j) => out.push(`${j + 1}. ${s}`));
    if (f.refs?.length) {
      out.push('', '**References:**', '');
      f.refs.forEach((r) => out.push(`- ${r}`));
    }
    out.push('');
  });

  out.push('', '## Open Ports', '');
  if (m.hosts.length === 0) out.push('_No hosts found._');
  m.hosts.forEach((h) => {
    out.push(`### ${h.host}`, '');
    if (h.ports.length === 0) { out.push('_No open ports._', ''); return; }
    out.push('| Port | Proto | Service | Version | Risk |', '|---:|---|---|---|---|');
    h.ports.forEach((p) => out.push(
      `| ${p.port} | ${p.proto} | ${mdCell(p.service)} | ${mdCell(p.version)} | ${p.risk.toUpperCase()} |`
    ));
    out.push('');
  });

  if (m.portAdvice.length) {
    out.push('## Hardening Recommendations', '');
    m.portAdvice.forEach((a) => {
      out.push(`### Port ${a.port} — ${a.label} (${a.risk.toUpperCase()})`, '');
      if (a.note) out.push(`${a.note}`, '');
      out.push(`Affected hosts: ${a.hosts.join(', ')}`, '');
      a.fixes.forEach((s) => out.push(`- ${s}`));
      out.push('');
    });
  }

  out.push('## Raw Output', '', '```', m.raw.replace(/```/g, "'''"), '```', '');
  out.push('---', '_Generated by Nmap Command Builder. Recommendations are general guidance — ' +
    'verify against vendor documentation before applying. Scan only systems you are authorized to test._', '');
  return out.join('\n');
}

// ─── HTML (pre PDF) ───────────────────────────────────────────────────────────
// Vsetky hodnoty zo skenu su neduveryhodne (bannery, nazvy hostov) → escapovat.

export function escapeHtml(v) {
  return String(v ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const SEV_COLOR = { critical: '#b00020', high: '#d32f2f', medium: '#e67e00', low: '#9a7d00', safe: '#2e7d32' };

export function toHtml(m) {
  const e = escapeHtml;
  const badge = (sev) =>
    `<span class="badge" style="background:${SEV_COLOR[sev] || '#555'}">${e(sev.toUpperCase())}</span>`;

  const findings = m.findings.length === 0
    ? '<p class="muted">No known vulnerabilities were detected by the NSE scripts that ran. ' +
      'Run <code>nmap -sV --script vuln,vulners &lt;target&gt;</code> for a vulnerability check.</p>'
    : [...m.findings]
      .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
      .map((f, i) => `
      <div class="finding sev-${e(f.severity)}">
        <h3>${i + 1}. ${badge(f.severity)} ${e(f.title)}</h3>
        <p class="meta">Host <b>${e(f.host)}</b>${f.port ? ` · port <b>${e(f.port)}</b>` : ''} · detected by <code>${e(f.script)}</code></p>
        ${f.evidence ? `<p class="meta">Evidence: <code>${e(f.evidence)}</code></p>` : ''}
        <p class="fix-title">How to fix</p>
        <ol>${f.fix.map((s) => `<li>${e(s)}</li>`).join('')}</ol>
        ${f.refs?.length ? `<p class="refs">${f.refs.map((r) => e(r)).join('<br>')}</p>` : ''}
      </div>`).join('');

  const hosts = m.hosts.length === 0 ? '<p class="muted">No hosts found.</p>' : m.hosts.map((h) => `
    <h3>${e(h.host)}</h3>
    ${h.ports.length === 0 ? '<p class="muted">No open ports.</p>' : `
    <table>
      <thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Version</th><th>Risk</th></tr></thead>
      <tbody>${h.ports.map((p) => `
        <tr><td class="num">${e(p.port)}</td><td>${e(p.proto)}</td><td>${e(p.service)}</td>
        <td>${e(p.version)}</td><td>${badge(p.risk)}</td></tr>`).join('')}
      </tbody>
    </table>`}`).join('');

  const advice = m.portAdvice.map((a) => `
    <div class="advice">
      <h3>Port ${e(a.port)} — ${e(a.label)} ${badge(a.risk)}</h3>
      ${a.note ? `<p class="meta">${e(a.note)}</p>` : ''}
      <p class="meta">Affected hosts: ${e(a.hosts.join(', '))}</p>
      <ul>${a.fixes.map((s) => `<li>${e(s)}</li>`).join('')}</ul>
    </div>`).join('');

  const cmp = m.comparison;
  const comparison = !cmp ? '' : `
  <h2>Changes Since Previous Scan</h2>
  <p class="meta">Compared with the scan from ${e(cmp.baselineTime)} (<code>${e(cmp.baselineCommand)}</code>).</p>
  ${cmp.sameCommand ? '' : '<p class="meta">⚠ Different command — some differences may come from different options.</p>'}
  ${cmp.sections.length === 0 ? '<p class="muted">No changes.</p>' : cmp.sections.map((sec) => `
    <div class="change change-${e(sec.tone)}">
      <h3>${e(sec.title)} (${sec.items.length})</h3>
      <ul>${sec.items.map((it) => `<li>${e(it)}</li>`).join('')}</ul>
    </div>`).join('')}`;

  const c = m.counts;
  return `<!doctype html>
<html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Nmap Scan Report</title>
<style>
  @page { size: A4; margin: 16mm 14mm; }
  body { font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; color: #1b1f1b; font-size: 11pt; line-height: 1.45; }
  h1 { font-size: 20pt; margin: 0 0 4px; } h2 { font-size: 14pt; border-bottom: 2px solid #1b5e20; padding-bottom: 3px; margin-top: 22px; }
  h3 { font-size: 11.5pt; margin: 14px 0 4px; }
  code, pre { font-family: Menlo, Consolas, monospace; font-size: 9pt; }
  .meta { margin: 2px 0; color: #444; font-size: 10pt; } .muted { color: #666; font-style: italic; }
  .head td { padding: 1px 12px 1px 0; font-size: 10pt; vertical-align: top; } .head td:first-child { color: #666; }
  .summary { display: flex; gap: 10px; margin: 8px 0; }
  .card { border: 1px solid #ccc; border-radius: 6px; padding: 6px 12px; min-width: 90px; }
  .card b { display: block; font-size: 16pt; }
  .badge { color: #fff; border-radius: 3px; padding: 1px 6px; font-size: 8pt; font-weight: 700; letter-spacing: .5px; vertical-align: middle; }
  .finding, .advice { border-left: 4px solid #999; padding: 2px 0 4px 12px; margin: 10px 0; page-break-inside: avoid; }
  .sev-critical { border-color: ${SEV_COLOR.critical}; } .sev-high { border-color: ${SEV_COLOR.high}; }
  .sev-medium { border-color: ${SEV_COLOR.medium}; } .sev-low { border-color: ${SEV_COLOR.low}; }
  .change { border-left: 4px solid #999; padding: 0 0 2px 12px; margin: 8px 0; page-break-inside: avoid; }
  .change-bad { border-color: ${SEV_COLOR.high}; } .change-good { border-color: ${SEV_COLOR.safe}; } .change-info { border-color: #0b57d0; }
  .fix-title { font-weight: 700; color: #1b5e20; margin: 6px 0 2px; }
  ol, ul { margin: 2px 0 4px 18px; padding: 0; } .refs { font-size: 8.5pt; color: #0b57d0; word-break: break-all; }
  table { border-collapse: collapse; width: 100%; font-size: 10pt; margin-bottom: 8px; }
  th, td { border-bottom: 1px solid #ddd; padding: 4px 6px; text-align: left; } th { background: #f1f5f1; } td.num { text-align: right; }
  pre { background: #f6f8f6; border: 1px solid #ddd; padding: 8px; white-space: pre-wrap; word-break: break-word; }
  footer { margin-top: 20px; font-size: 8.5pt; color: #666; border-top: 1px solid #ddd; padding-top: 6px; }
</style></head>
<body>
  <h1>Nmap Scan Report</h1>
  <table class="head">
    <tr><td>Target</td><td><code>${e(m.target)}</code></td></tr>
    <tr><td>Command</td><td><code>${e(m.command)}</code></td></tr>
    <tr><td>Date</td><td>${e(m.timestamp)}</td></tr>
    ${m.nmapVersion ? `<tr><td>Nmap</td><td>${e(m.nmapVersion)}</td></tr>` : ''}
  </table>

  <h2>Summary</h2>
  <div class="summary">
    <div class="card">Hosts up<b>${m.hosts.length}</b></div>
    <div class="card">Open ports<b>${m.openPortCount}</b></div>
    <div class="card">Critical<b style="color:${SEV_COLOR.critical}">${c.critical}</b></div>
    <div class="card">High<b style="color:${SEV_COLOR.high}">${c.high}</b></div>
    <div class="card">Medium<b style="color:${SEV_COLOR.medium}">${c.medium}</b></div>
    <div class="card">Low<b style="color:${SEV_COLOR.low}">${c.low}</b></div>
  </div>

  ${comparison}

  <h2>Vulnerabilities &amp; Fixes</h2>
  ${findings}

  <h2>Open Ports</h2>
  ${hosts}

  ${advice ? `<h2>Hardening Recommendations</h2>${advice}` : ''}

  <h2>Raw Output</h2>
  <pre>${e(m.raw)}</pre>

  <footer>Generated by Nmap Command Builder. Recommendations are general guidance — verify against vendor
  documentation before applying. Scan only systems you are authorized to test.</footer>
</body></html>`;
}

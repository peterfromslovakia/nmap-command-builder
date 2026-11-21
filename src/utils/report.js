import { parseFindings, SEVERITY_ORDER } from './findings';
import { getPortRisk } from '../data/portRisk';
import { getPortIntel } from '../data/portIntel';
import { getPortFixes } from '../data/remediation';
import { labels, tr } from '../i18n/report';

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
 * Zmeny oproti predchadzajucemu skenu ako jednoduche textove riadky
 * (spolocne pre Markdown aj PDF). `diff` je vysledok diffScans().
 */
export function changeSections(diff, lang = 'en') {
  if (!diff) return [];
  const L = labels(lang);
  const sk = lang === 'sk';
  const port = (p) => `${p.port}/${p.proto} ${p.service}${p.version ? ` ${p.version}` : ''} — ${p.host}`;
  const finding = (f) => `[${L.sev[f.severity] || f.severity}] ${tr(f.title, lang)} — ${f.host}${f.port ? ` · ${f.port}` : ''}`;
  const sections = [
    ['New vulnerabilities', 'bad', diff.newFindings.map(finding)],
    ['New open ports', 'bad', diff.openedPorts.map(port)],
    ['New hosts', 'bad', diff.newHosts.map((h) => `${h.host} (${h.ports.map((p) => p.port).join(', ') || (sk ? 'žiadne otvorené porty' : 'no open ports')})`)],
    ['Version changes', 'info', diff.changedVersions.map((c) => `${c.port}/${c.proto} ${c.service}: ${c.from} → ${c.to} — ${c.host}`)],
    ['Fixed vulnerabilities', 'good', diff.resolvedFindings.map(finding)],
    ['Closed ports', 'good', diff.closedPorts.map(port)],
    ['Hosts not found', 'info', diff.goneHosts.map((h) => `${h.host} (${sk ? 'nedostupné alebo filtrované' : 'down or filtered'})`)],
  ];
  return sections
    .filter(([, , items]) => items.length > 0)
    .map(([key, tone, items]) => ({ key, title: L.changeTitles[key], tone, items }));
}

/**
 * Celkove riziko: najzavaznejsi nalez; bez nalezov aspon "medium" pri rizikovom
 * sprístupnenom porte (napr. Telnet, SMB, RDP) a "low" pri porte na kontrolu.
 */
export function overallRisk(findings, hosts) {
  for (const sev of ['critical', 'high', 'medium']) {
    if (findings.some((f) => f.severity === sev)) return sev;
  }
  const ports = hosts.flatMap((h) => h.ports);
  if (ports.some((p) => p.risk === 'high')) return 'medium';
  if (findings.length > 0 || ports.some((p) => p.risk === 'medium')) return 'low';
  return 'none';
}

const clean = (v, max = 120) => String(v ?? '').replace(/[\r\n\t]+/g, ' ').trim().slice(0, max);

/** Udaje o teste (kto, pre koho, na zaklade coho) — vsetko volitelne. */
export function normalizeMeta(meta = {}) {
  return {
    lang: meta.lang === 'sk' ? 'sk' : 'en',
    tester: clean(meta.tester),
    organization: clean(meta.organization),
    client: clean(meta.client),
    authorization: clean(meta.authorization),
  };
}

/**
 * Datovy model reportu — spolocny pre Markdown aj HTML/PDF.
 */
export function buildReportModel({ text, command, target, timestamp, nmapVersion, comparison, meta }) {
  const m = normalizeMeta(meta);
  const hosts = parseHosts(text);
  const findings = parseFindings(text).sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

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
    ...m,
    command, target, timestamp, nmapVersion: nmapVersion || '',
    hosts, findings, portAdvice, counts,
    risk: overallRisk(findings, hosts),
    // comparison: { baselineTime, baselineCommand, sameCommand, sections }
    comparison: comparison && comparison.diff ? {
      baselineTime: comparison.baselineTime,
      baselineCommand: comparison.baselineCommand,
      sameCommand: comparison.diff.sameCommand,
      sections: changeSections(comparison.diff, m.lang),
    } : null,
    openPortCount: hosts.reduce((n, h) => n + h.ports.length, 0),
    raw: String(text || '').trim(),
  };
}

const detailRows = (m, L) => [
  [L.target, m.target, true],
  [L.command, m.command, true],
  [L.date, m.timestamp],
  m.nmapVersion && [L.nmap, m.nmapVersion],
  [L.performedBy, m.tester || L.notStated, false, !m.tester],
  m.organization && [L.organization, m.organization],
  m.client && [L.client, m.client],
  m.authorization && [L.authorization, m.authorization],
].filter(Boolean);

// ─── Markdown ─────────────────────────────────────────────────────────────────

const mdCell = (v) => String(v ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
const mdCode = (v) => `\`${String(v ?? '').replace(/`/g, "'")}\``;

export function toMarkdown(m) {
  const L = labels(m.lang);
  const t = (s) => tr(s, m.lang);
  const sevLabel = (s) => (L.sev[s] || s).toUpperCase();
  const out = [];

  out.push(`# ${L.title}`, '', `> ${L.confidential}`, '');
  out.push(`## ${L.reportDetails}`, '');
  detailRows(m, L).forEach(([k, v, code, dim]) => out.push(`- **${k}:** ${code ? mdCode(v) : dim ? `_${v}_` : mdCell(v)}`));

  out.push('', `## ${L.executiveSummary}`, '');
  out.push(`**${L.overallRisk}: ${sevLabel(m.risk)}** — ${L.riskText[m.risk]}`, '');
  out.push(`| ${L.hostsUp} | ${L.openPorts} | ${L.sev.critical} | ${L.sev.high} | ${L.sev.medium} | ${L.sev.low} |`);
  out.push('|---:|---:|---:|---:|---:|---:|');
  out.push(`| ${m.hosts.length} | ${m.openPortCount} | ${m.counts.critical} | ${m.counts.high} | ${m.counts.medium} | ${m.counts.low} |`);

  if (m.findings.length) {
    out.push('', `## ${L.findingsOverview}`, '');
    out.push(`| ${L.colNo} | ${L.colSeverity} | ${L.colFinding} | ${L.colHost} | ${L.colPort} |`, '|---:|---|---|---|---|');
    m.findings.forEach((f, i) => out.push(
      `| ${i + 1} | ${sevLabel(f.severity)} | ${mdCell(t(f.title))} | ${mdCell(f.host)} | ${mdCell(f.port || '—')} |`
    ));
  }

  if (m.comparison) {
    const cmp = m.comparison;
    out.push('', `## ${L.changes}`, '');
    out.push(L.comparedWith(cmp.baselineTime, mdCode(cmp.baselineCommand)));
    if (!cmp.sameCommand) out.push('', `> ${L.differentCommand}`);
    if (cmp.sections.length === 0) out.push('', `_${L.noChanges}_`);
    cmp.sections.forEach((sec) => {
      out.push('', `**${sec.title}**`, '');
      sec.items.forEach((it) => out.push(`- ${mdCell(it)}`));
    });
  }

  out.push('', `## ${L.vulnsAndFixes}`, '');
  if (m.findings.length === 0) out.push(`_${L.noFindings}_`);
  m.findings.forEach((f, i) => {
    out.push(`### ${i + 1}. [${sevLabel(f.severity)}] ${t(f.title)}`, '');
    out.push(`- **${L.host}:** ${f.host}${f.port ? ` — ${L.port} ${f.port}` : ''}`);
    out.push(`- **${L.detectedBy}:** ${mdCode(f.script)}`);
    if (f.evidence) out.push(`- **${L.evidence}:** ${f.evidence}`);
    out.push('', `**${L.howToFix}:**`, '');
    f.fix.forEach((s, j) => out.push(`${j + 1}. ${t(s)}`));
    if (f.refs?.length) {
      out.push('', `**${L.references}:**`, '');
      f.refs.forEach((r) => out.push(`- ${r}`));
    }
    out.push('');
  });

  out.push('', `## ${L.openPortsTitle}`, '');
  if (m.hosts.length === 0) out.push(`_${L.noHosts}_`);
  m.hosts.forEach((h) => {
    out.push(`### ${h.host}`, '');
    if (h.ports.length === 0) { out.push(`_${L.noOpenPorts}_`, ''); return; }
    out.push(`| ${L.colPort} | ${L.colProto} | ${L.colService} | ${L.colVersion} | ${L.colRisk} |`, '|---:|---|---|---|---|');
    h.ports.forEach((p) => out.push(
      `| ${p.port} | ${p.proto} | ${mdCell(p.service)} | ${mdCell(p.version)} | ${sevLabel(p.risk)} |`
    ));
    out.push('');
  });

  if (m.portAdvice.length) {
    out.push(`## ${L.hardening}`, '');
    m.portAdvice.forEach((a) => {
      out.push(`### ${L.colPort} ${a.port} — ${a.label} (${sevLabel(a.risk)})`, '');
      if (a.note) out.push(`${t(a.note)}`, '');
      out.push(`${L.affectedHosts}: ${a.hosts.join(', ')}`, '');
      a.fixes.forEach((s) => out.push(`- ${t(s)}`));
      out.push('');
    });
  }

  out.push(`## ${L.scopeTitle}`, '', L.scope, '');
  out.push(`## ${L.rawOutput}`, '', '```', m.raw.replace(/```/g, "'''"), '```', '');
  out.push('---', `_${L.footer}${m.tester ? ` · ${m.tester}` : ''} · ${m.timestamp}_`, '');
  return out.join('\n');
}

// ─── HTML (pre PDF) ───────────────────────────────────────────────────────────
// Vsetky hodnoty zo skenu su neduveryhodne (bannery, nazvy hostov) → escapovat.

export function escapeHtml(v) {
  return String(v ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const SEV_COLOR = {
  critical: '#b00020', high: '#d32f2f', medium: '#e67e00', low: '#9a7d00', safe: '#2e7d32', none: '#2e7d32',
};

export function toHtml(m) {
  const e = escapeHtml;
  const L = labels(m.lang);
  const t = (s) => tr(s, m.lang);
  const badge = (sev) =>
    `<span class="badge" style="background:${SEV_COLOR[sev] || '#555'}">${e((L.sev[sev] || sev).toUpperCase())}</span>`;

  const details = detailRows(m, L).map(([k, v, code, dim]) =>
    `<tr><td>${e(k)}</td><td>${code ? `<code>${e(v)}</code>` : dim ? `<span class="muted">${e(v)}</span>` : e(v)}</td></tr>`).join('');

  const overview = m.findings.length === 0 ? '' : `
  <h2>${e(L.findingsOverview)}</h2>
  <table>
    <thead><tr><th class="num">${e(L.colNo)}</th><th>${e(L.colSeverity)}</th><th>${e(L.colFinding)}</th><th>${e(L.colHost)}</th><th>${e(L.colPort)}</th></tr></thead>
    <tbody>${m.findings.map((f, i) => `
      <tr><td class="num">${i + 1}</td><td>${badge(f.severity)}</td><td>${e(t(f.title))}</td><td>${e(f.host)}</td><td>${e(f.port || '—')}</td></tr>`).join('')}
    </tbody>
  </table>`;

  const findings = m.findings.length === 0
    ? `<p class="muted">${e(L.noFindings)}</p>`
    : m.findings.map((f, i) => `
      <div class="finding sev-${e(f.severity)}">
        <h3>${i + 1}. ${badge(f.severity)} ${e(t(f.title))}</h3>
        <p class="meta">${e(L.host)} <b>${e(f.host)}</b>${f.port ? ` · ${e(L.port)} <b>${e(f.port)}</b>` : ''} · ${e(L.detectedBy)} <code>${e(f.script)}</code></p>
        ${f.evidence ? `<p class="meta">${e(L.evidence)}: <code>${e(f.evidence)}</code></p>` : ''}
        <p class="fix-title">${e(L.howToFix)}</p>
        <ol>${f.fix.map((s) => `<li>${e(t(s))}</li>`).join('')}</ol>
        ${f.refs?.length ? `<p class="refs">${f.refs.map((r) => e(r)).join('<br>')}</p>` : ''}
      </div>`).join('');

  const hosts = m.hosts.length === 0 ? `<p class="muted">${e(L.noHosts)}</p>` : m.hosts.map((h) => `
    <h3>${e(h.host)}</h3>
    ${h.ports.length === 0 ? `<p class="muted">${e(L.noOpenPorts)}</p>` : `
    <table>
      <thead><tr><th class="num">${e(L.colPort)}</th><th>${e(L.colProto)}</th><th>${e(L.colService)}</th><th>${e(L.colVersion)}</th><th>${e(L.colRisk)}</th></tr></thead>
      <tbody>${h.ports.map((p) => `
        <tr><td class="num">${e(p.port)}</td><td>${e(p.proto)}</td><td>${e(p.service)}</td>
        <td>${e(p.version)}</td><td>${badge(p.risk)}</td></tr>`).join('')}
      </tbody>
    </table>`}`).join('');

  const advice = m.portAdvice.map((a) => `
    <div class="advice">
      <h3>${e(L.colPort)} ${e(a.port)} — ${e(a.label)} ${badge(a.risk)}</h3>
      ${a.note ? `<p class="meta">${e(t(a.note))}</p>` : ''}
      <p class="meta">${e(L.affectedHosts)}: ${e(a.hosts.join(', '))}</p>
      <ul>${a.fixes.map((s) => `<li>${e(t(s))}</li>`).join('')}</ul>
    </div>`).join('');

  const cmp = m.comparison;
  const comparison = !cmp ? '' : `
  <h2>${e(L.changes)}</h2>
  <p class="meta">${e(L.comparedWith(cmp.baselineTime, cmp.baselineCommand))}</p>
  ${cmp.sameCommand ? '' : `<p class="meta">⚠ ${e(L.differentCommand)}</p>`}
  ${cmp.sections.length === 0 ? `<p class="muted">${e(L.noChanges)}</p>` : cmp.sections.map((sec) => `
    <div class="change change-${e(sec.tone)}">
      <h3>${e(sec.title)} (${sec.items.length})</h3>
      <ul>${sec.items.map((it) => `<li>${e(it)}</li>`).join('')}</ul>
    </div>`).join('')}`;

  const c = m.counts;
  return `<!doctype html>
<html lang="${e(m.lang)}"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>${e(L.title)}</title>
<style>
  @page { size: A4; margin: 16mm 14mm 18mm; }
  body { font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; color: #1b1f1b; font-size: 10.5pt; line-height: 1.45; }
  h1 { font-size: 20pt; margin: 0 0 2px; color: #123d14; }
  h2 { font-size: 13.5pt; border-bottom: 2px solid #1b5e20; padding-bottom: 3px; margin-top: 22px; color: #123d14; }
  h3 { font-size: 11pt; margin: 14px 0 4px; }
  code, pre { font-family: Menlo, Consolas, monospace; font-size: 8.8pt; }
  .meta { margin: 2px 0; color: #444; font-size: 9.8pt; } .muted { color: #777; font-style: italic; }
  .confidential { border: 1px solid #b00020; color: #b00020; font-size: 8.5pt; font-weight: 700; letter-spacing: .3px; padding: 4px 8px; margin: 6px 0 12px; }
  .head { width: auto; border: none; margin: 0; } .head td { border: none; padding: 1px 14px 1px 0; font-size: 9.8pt; vertical-align: top; }
  .head td:first-child { color: #666; white-space: nowrap; }
  .risk { display: flex; gap: 14px; align-items: center; border-radius: 6px; padding: 10px 14px; margin: 8px 0; color: #fff; page-break-inside: avoid; }
  .risk b { font-size: 15pt; white-space: nowrap; } .risk span { font-size: 10pt; }
  .summary { display: flex; gap: 8px; margin: 8px 0; }
  .card { border: 1px solid #ccc; border-radius: 6px; padding: 5px 10px; flex: 1; font-size: 9pt; color: #555; }
  .card b { display: block; font-size: 15pt; color: #1b1f1b; }
  .badge { color: #fff; border-radius: 3px; padding: 1px 6px; font-size: 7.8pt; font-weight: 700; letter-spacing: .5px; vertical-align: middle; white-space: nowrap; }
  .finding, .advice, .change { border-left: 4px solid #999; padding: 2px 0 4px 12px; margin: 10px 0; page-break-inside: avoid; }
  .sev-critical { border-color: ${SEV_COLOR.critical}; } .sev-high { border-color: ${SEV_COLOR.high}; }
  .sev-medium { border-color: ${SEV_COLOR.medium}; } .sev-low { border-color: ${SEV_COLOR.low}; }
  .change-bad { border-color: ${SEV_COLOR.high}; } .change-good { border-color: ${SEV_COLOR.safe}; } .change-info { border-color: #0b57d0; }
  .fix-title { font-weight: 700; color: #1b5e20; margin: 6px 0 2px; }
  ol, ul { margin: 2px 0 4px 18px; padding: 0; } .refs { font-size: 8.3pt; color: #0b57d0; word-break: break-all; }
  table { border-collapse: collapse; width: 100%; font-size: 9.5pt; margin-bottom: 8px; }
  thead { display: table-header-group; } tr { page-break-inside: avoid; }
  th, td { border-bottom: 1px solid #ddd; padding: 4px 6px; text-align: left; vertical-align: top; } th { background: #eef4ee; } .num { text-align: right; }
  pre { background: #f6f8f6; border: 1px solid #ddd; padding: 8px; white-space: pre-wrap; word-break: break-word; font-size: 8pt; }
  .scope { font-size: 9.5pt; color: #333; }
  footer { margin-top: 20px; font-size: 8.3pt; color: #666; border-top: 1px solid #ddd; padding-top: 6px; }
</style></head>
<body>
  <h1>${e(L.title)}</h1>
  <div class="confidential">${e(L.confidential)}</div>

  <table class="head">${details}</table>

  <h2>${e(L.executiveSummary)}</h2>
  <div class="risk" style="background:${SEV_COLOR[m.risk]}">
    <b>${e(L.overallRisk)}: ${e((L.sev[m.risk] || m.risk).toUpperCase())}</b>
    <span>${e(L.riskText[m.risk])}</span>
  </div>
  <div class="summary">
    <div class="card">${e(L.hostsUp)}<b>${m.hosts.length}</b></div>
    <div class="card">${e(L.openPorts)}<b>${m.openPortCount}</b></div>
    <div class="card">${e(L.sev.critical)}<b style="color:${SEV_COLOR.critical}">${c.critical}</b></div>
    <div class="card">${e(L.sev.high)}<b style="color:${SEV_COLOR.high}">${c.high}</b></div>
    <div class="card">${e(L.sev.medium)}<b style="color:${SEV_COLOR.medium}">${c.medium}</b></div>
    <div class="card">${e(L.sev.low)}<b style="color:${SEV_COLOR.low}">${c.low}</b></div>
  </div>
  ${overview}
  ${comparison}

  <h2>${e(L.vulnsAndFixes)}</h2>
  ${findings}

  <h2>${e(L.openPortsTitle)}</h2>
  ${hosts}

  ${advice ? `<h2>${e(L.hardening)}</h2>${advice}` : ''}

  <h2>${e(L.scopeTitle)}</h2>
  <p class="scope">${e(L.scope)}</p>

  <h2>${e(L.rawOutput)}</h2>
  <pre>${e(m.raw)}</pre>

  <footer>${e(L.footer)}${m.tester ? ` · ${e(m.tester)}` : ''} · ${e(m.timestamp)}</footer>
</body></html>`;
}

/** Text pre pätu kazdej strany PDF (cislo strany doplni Chromium). */
export function pdfFooterLabel(m) {
  const L = labels(m.lang);
  return { title: L.title, page: L.page, tester: m.tester };
}

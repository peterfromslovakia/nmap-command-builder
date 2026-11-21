import { parseFindings, SEVERITY_ORDER } from './findings';
import { buildTopology, hostIp } from './topology';
import { applyIntel } from './intel';
import { getPortRisk } from '../data/portRisk';
import { getPortIntel } from '../data/portIntel';
import { getPortFixes } from '../data/remediation';
import { getLabel } from './deviceLabels';
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
 * spristupnenom porte (napr. Telnet, SMB, RDP) a "low" pri porte na kontrolu.
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

/** Pouzite techniky skenu podla prikazu (pre kapitolu Metodika). */
export function describeTechniques(command, L, { intel = false } = {}) {
  const a = String(command || '').split(/\s+/).filter(Boolean).slice(1);
  const has = (f) => a.includes(f);
  const val = (f) => { const i = a.indexOf(f); return i >= 0 ? a[i + 1] : ''; };
  const t = L.tech;
  const out = [];
  if (has('-sn')) out.push(t.pingOnly);
  else {
    if (a.some((x) => /^-P[SA]/.test(x))) out.push(t.discovery);
    if (has('-sS')) out.push(t.syn); else out.push(t.connect);
    if (has('-sU')) out.push(t.udp);
    if (has('-p-')) out.push(t.allPorts);
    else if (has('-p')) out.push(t.ports(val('-p')));
    else if (has('-F')) out.push(t.topPorts);
    else if (has('--top-ports')) out.push(t.ports(`top ${val('--top-ports')}`));
    else out.push(t.defaultPorts);
  }
  if (has('-sV') || has('-A')) out.push(t.version);
  if (has('-O') || has('-A')) out.push(t.os);
  if (has('--script')) out.push(t.scripts(val('--script')));
  else if (has('-sC') || has('-A')) out.push(t.scripts('default'));
  const timing = a.find((x) => /^-T[0-5]$/.test(x));
  if (timing) out.push(t.timing(timing.slice(2)));
  if (intel) out.push(t.intel);
  return out;
}

const timeframeKey = (f) => (f.exploited ? 'exploited' : f.severity);

/**
 * Datovy model reportu — spolocny pre Markdown aj HTML/PDF.
 * findings: obohatene nalezy (applyIntel); ak chyba, vyparsuju sa z textu.
 */
/** Topologia pre report: ku kazdemu zariadeniu aj cisla nalezov (F-01…). */
function reportMap(devices, findings, gatewayIp, localIps, target) {
  const topo = buildTopology({ devices, gatewayIp, localIps, findings, target });
  const refs = (ip) => findings.filter((f) => hostIp(f.host) === ip).map((f) => f.ref);
  const add = (d) => d && { ...d, refs: refs(d.ip) };
  const addGroups = (groups) => groups.map((g) => ({ ...g, devices: g.devices.map(add) }));
  return { ...topo, gateway: add(topo.gateway), groups: addGroups(topo.groups), segments: topo.segments.map((sg) => ({ ...sg, groups: addGroups(sg.groups) })) };
}

const RAW_LIMIT = 2 * 1024 * 1024;
function rawAppendix(raw) {
  if (raw.length <= RAW_LIMIT) return { raw, rawTruncated: false };
  const half = RAW_LIMIT / 2;
  return { raw: `${raw.slice(0, half)}\n\n[…]\n\n${raw.slice(-half)}`, rawTruncated: true, rawLength: raw.length };
}

export function buildReportModel({
  text, command, target, timestamp, nmapVersion, comparison, meta, findings: given, intelMeta, inventory, generatedAt,
  gatewayIp = null, localIps = [], labels: deviceLabels = null,
}) {
  const m = normalizeMeta(meta);
  const L = labels(m.lang);
  const hosts = parseHosts(text);
  const findings = (given || applyIntel(parseFindings(text), null))
    .slice()
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || Number(Boolean(b.exploited)) - Number(Boolean(a.exploited)))
    .map((f, i) => {
      const details = f.cveDetails || [];
      const best = details.filter((c) => c.nvd && c.nvd.score != null).sort((x, y) => y.nvd.score - x.nvd.score)[0];
      const described = details.find((c) => c.nvd && c.nvd.description);
      return {
        ...f,
        ref: `F-${String(i + 1).padStart(2, '0')}`,
        cvss: best ? best.nvd.score : details.reduce((mx, c) => (c.score != null && c.score > (mx ?? -1) ? c.score : mx), null),
        vector: best ? best.nvd.vector : '',
        cwe: [...new Set(details.flatMap((c) => (c.nvd && c.nvd.cwe) || []))].slice(0, 4),
        nvdDescription: described ? described.nvd.description : '',
        nvdDescriptionCve: described ? described.id : '',
        timeframe: timeframeKey(f),
      };
    });

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

  const actions = findings
    .filter((f) => f.exploited || f.severity === 'critical' || f.severity === 'high')
    .slice(0, 5)
    .map((f) => ({ ref: f.ref, title: f.title, host: f.host, timeframe: f.timeframe, exploited: Boolean(f.exploited) }));

  const usedIntel = Boolean(intelMeta && (intelMeta.kevVersion || findings.some((f) => f.cveDetails?.some((c) => c.epss != null || c.nvd))));

  return {
    ...m,
    command, target, timestamp, nmapVersion: nmapVersion || '',
    generatedAt: generatedAt || timestamp,
    hosts, findings, portAdvice, counts, actions,
    exploitedCount: findings.filter((f) => f.exploited).length,
    risk: overallRisk(findings, hosts),
    techniques: describeTechniques(command, L, { intel: usedIntel }),
    intelMeta: usedIntel ? { kevVersion: (intelMeta && intelMeta.kevVersion) || '' } : null,
    inventory: Array.isArray(inventory) && inventory.length > 0 ? inventory : null,
    deviceLabels: deviceLabels || null,
    // Mapa siete (priloha A) — len pri skene siete s aspon 2 zariadeniami
    map: Array.isArray(inventory) && inventory.length > 1 ? reportMap(inventory, findings, gatewayIp, localIps, target) : null,
    // comparison: { baselineTime, baselineCommand, sameCommand, sections }
    comparison: comparison && comparison.diff ? {
      baselineTime: comparison.baselineTime,
      baselineCommand: comparison.baselineCommand,
      sameCommand: comparison.diff.sameCommand,
      sections: changeSections(comparison.diff, m.lang),
    } : null,
    openPortCount: hosts.reduce((n, h) => n + h.ports.length, 0),
    // Priloha s vystupom skenera: max. ~2 MB (PDF ma limit 20 MB); zaciatok aj koniec.
    ...rawAppendix(String(text || '').trim()),
  };
}

/** Kapitoly reportu v poradi (pre obsah aj cislovanie). */
export function reportSections(m) {
  const L = labels(m.lang);
  return [
    ['summary', L.executiveSummary],
    ['scope', L.scopeMethodology],
    ['rating', L.ratingTitle],
    m.findings.length > 0 && ['overview', L.findingsOverview],
    ['findings', L.vulnsAndFixes],
    m.comparison && ['changes', L.changes],
    m.inventory && ['inventory', L.assetInventory],
    ['ports', L.openPortsTitle],
    m.portAdvice.length > 0 && ['hardening', L.hardening],
    ['signoff', L.signOff],
    m.map && ['map', L.networkMap],
    ['raw', L.rawOutput],
  ].filter(Boolean).map(([id, title], i) => ({ id, title, no: i + 1 }));
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

const epssText = (v) => (v == null ? '—' : `${(v * 100) >= 10 ? Math.round(v * 100) : (v * 100).toFixed(1)} %`);

// ─── Markdown ─────────────────────────────────────────────────────────────────

const mdCell = (v) => String(v ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
const mdCode = (v) => `\`${String(v ?? '').replace(/`/g, "'")}\``;

export function toMarkdown(m) {
  const L = labels(m.lang);
  const t = (s) => tr(s, m.lang);
  const sevLabel = (s) => (L.sev[s] || s).toUpperCase();
  const sec = Object.fromEntries(reportSections(m).map((s) => [s.id, s]));
  const h2 = (id) => `## ${sec[id].no}. ${sec[id].title}`;
  const out = [];

  out.push(`# ${L.title}`, '', `**${L.coverSubtitle}**`, '', `> ${L.confidential}`, '');
  out.push(`## ${L.reportDetails}`, '');
  detailRows(m, L).forEach(([k, v, code, dim]) => out.push(`- **${k}:** ${code ? mdCode(v) : dim ? `_${v}_` : mdCell(v)}`));
  out.push(`- **${L.reportDate}:** ${m.generatedAt}`, `- **${L.classification}:** ${L.classificationValue}`);

  out.push('', `## ${L.contents}`, '');
  reportSections(m).forEach((s) => out.push(`${s.no}. ${s.title}`));

  out.push('', h2('summary'), '');
  out.push(`**${L.overallRisk}: ${sevLabel(m.risk)}** — ${L.riskText[m.risk]}`, '');
  out.push(`| ${L.hostsUp} | ${L.openPorts} | ${L.sev.critical} | ${L.sev.high} | ${L.sev.medium} | ${L.sev.low} | ${L.colKev} |`);
  out.push('|---:|---:|---:|---:|---:|---:|---:|');
  out.push(`| ${m.hosts.length} | ${m.openPortCount} | ${m.counts.critical} | ${m.counts.high} | ${m.counts.medium} | ${m.counts.low} | ${m.exploitedCount} |`);
  out.push('', `**${L.priorityActions}**`, '');
  if (m.actions.length === 0) out.push(`_${L.noActions}_`);
  m.actions.forEach((a, i) => out.push(
    `${i + 1}. ${L.actionFix(t(a.title), a.host)} (${a.ref}) — ${a.exploited ? L.actionExploited : `${L.colTimeframe.toLowerCase()} ${L.timeframe[a.timeframe]}`}`
  ));

  out.push('', h2('scope'), '');
  out.push(`- **${L.targetsInScope}:** ${mdCode(m.target)}`);
  out.push(`- **${L.scanWindow}:** ${m.timestamp}`);
  out.push(`- **${L.tool}:** ${m.nmapVersion || 'Nmap'} · Nmap Command Builder`);
  if (m.authorization) out.push(`- **${L.authorization}:** ${mdCell(m.authorization)}`);
  out.push(`- **${L.techniques}:**`);
  m.techniques.forEach((x) => out.push(`  - ${x}`));
  out.push('', L.scope);

  out.push('', h2('rating'), '', L.ratingIntro, '');
  out.push(`| ${L.colSeverity} | ${L.colCvss} | ${L.colMeaning} | ${L.colTimeframe} |`, '|---|---|---|---|');
  [['critical', '9.0–10.0'], ['high', '7.0–8.9'], ['medium', '4.0–6.9'], ['low', '0.1–3.9']].forEach(([s, r]) =>
    out.push(`| ${sevLabel(s)} | ${r} | ${L.meaning[s]} | ${L.timeframe[s]} |`));
  out.push(`| ${L.exploitedNow} | — | ${L.escalatedNote} | ${L.timeframe.exploited} |`);

  if (sec.overview) {
    out.push('', h2('overview'), '');
    out.push(`| ${L.colId} | ${L.colSeverity} | ${L.colFinding} | ${L.colHost} | ${L.colKev} | ${L.colEpss} | ${L.colDue} |`, '|---|---|---|---|---|---:|---|');
    m.findings.forEach((f) => out.push(
      `| ${f.ref} | ${sevLabel(f.severity)} | ${mdCell(t(f.title))} | ${mdCell(f.host)}${f.port ? ` · ${f.port}` : ''} | ${f.exploited ? L.yes : L.no} | ${epssText(f.epssMax)} | ${L.timeframe[f.timeframe]} |`
    ));
  }

  out.push('', h2('findings'), '');
  if (m.findings.length === 0) out.push(`_${L.noFindings}_`);
  m.findings.forEach((f) => {
    out.push(`### ${f.ref} — [${sevLabel(f.severity)}] ${t(f.title)}`, '');
    if (f.exploited) out.push(`> **${L.exploitedNow}${f.ransomware ? ` — ${L.ransomwareUse}` : ''}.** ${L.kevNote(f.kevDue)}${f.escalated ? ` ${L.escalatedNote}` : ''}`, '');
    out.push(`- **${L.affectedAsset}:** ${f.host}${f.port ? ` — ${L.port} ${f.port}` : ''}`);
    if (f.cvss != null) out.push(`- **CVSS:** ${f.cvss}${f.vector ? ` (${mdCode(f.vector)})` : ''}`);
    if (f.epssMax != null) out.push(`- **EPSS:** ${epssText(f.epssMax)}`);
    if (f.cwe.length) out.push(`- **${L.weakness}:** ${f.cwe.join(', ')}`);
    out.push(`- **${L.colTimeframe}:** ${L.timeframe[f.timeframe]}`);
    out.push(`- **${L.detectedBy}:** ${mdCode(f.script)}`);
    if (f.evidence) out.push(`- **${L.evidence}:** ${f.evidence}`);
    out.push('', `**${L.impact}:** ${L.impactText[f.severity]}`);
    if (f.nvdDescription) out.push('', `**${L.descriptionNvd} — ${f.nvdDescriptionCve}:** ${f.nvdDescription}`);
    if (f.cveDetails?.length) {
      out.push('', `**${L.relatedCves}:**`, '', `| ${L.colCve} | CVSS | EPSS | ${L.colKev} |`, '|---|---:|---:|---|');
      f.cveDetails.slice(0, 12).forEach((c) => out.push(`| ${c.id} | ${c.score ?? '—'} | ${epssText(c.epss)} | ${c.kev ? L.yes : L.no} |`));
    }
    out.push('', `**${L.howToFix}:**`, '');
    f.fix.forEach((s, j) => out.push(`${j + 1}. ${t(s)}`));
    if (f.refs?.length) {
      out.push('', `**${L.references}:**`, '');
      f.refs.forEach((r) => out.push(`- ${r}`));
    }
    out.push('');
  });

  if (m.comparison) {
    const cmp = m.comparison;
    out.push('', h2('changes'), '');
    out.push(L.comparedWith(cmp.baselineTime, mdCode(cmp.baselineCommand)));
    if (!cmp.sameCommand) out.push('', `> ${L.differentCommand}`);
    if (cmp.sections.length === 0) out.push('', `_${L.noChanges}_`);
    cmp.sections.forEach((s) => {
      out.push('', `**${s.title}**`, '');
      s.items.forEach((it) => out.push(`- ${mdCell(it)}`));
    });
  }

  if (m.inventory) {
    out.push('', h2('inventory'), '');
    const mdInvLabel = (d) => getLabel(d.mac, d.ip, m.deviceLabels);
    const mdHasLabels = m.deviceLabels && m.inventory.some(mdInvLabel);
    if (mdHasLabels) {
      out.push(`| ${L.colIp} | ${L.colType} | ${L.colLabel || 'Label'} | ${L.colName} | ${L.colMac} | ${L.colOpenPorts} |`, '|---|---|---|---|---|---|');
      m.inventory.forEach((d) => out.push(
        `| ${d.ip} | ${L.deviceTypes[d.type] || d.type} | ${mdCell(mdInvLabel(d) || '—')} | ${mdCell(d.hostname || '—')} | ${mdCell([d.mac, d.randomizedMac ? L.randomMac : d.vendor].filter(Boolean).join(' · ') || '—')} | ${mdCell(d.ports.map((p) => p.port).join(', ') || '—')} |`
      ));
    } else {
      out.push(`| ${L.colIp} | ${L.colType} | ${L.colName} | ${L.colMac} | ${L.colOpenPorts} |`, '|---|---|---|---|---|');
      m.inventory.forEach((d) => out.push(
        `| ${d.ip} | ${L.deviceTypes[d.type] || d.type} | ${mdCell(d.hostname || '—')} | ${mdCell([d.mac, d.randomizedMac ? L.randomMac : d.vendor].filter(Boolean).join(' · ') || '—')} | ${mdCell(d.ports.map((p) => p.port).join(', ') || '—')} |`
      ));
    }
  }

  out.push('', h2('ports'), '');
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

  if (sec.hardening) {
    out.push(h2('hardening'), '');
    m.portAdvice.forEach((a) => {
      out.push(`### ${L.colPort} ${a.port} — ${a.label} (${sevLabel(a.risk)})`, '');
      if (a.note) out.push(`${t(a.note)}`, '');
      out.push(`${L.affectedHosts}: ${a.hosts.join(', ')}`, '');
      a.fixes.forEach((s) => out.push(`- ${t(s)}`));
      out.push('');
    });
  }

  out.push(h2('signoff'), '');
  out.push(`| | ${L.colName} | ${L.signDate} | ${L.signature} |`, '|---|---|---|---|');
  out.push(`| ${L.signPreparedBy} | ${mdCell(m.tester || ' ')} | ${m.generatedAt} | |`);
  out.push(`| ${L.signApprovedBy} | | | |`, '');

  if (m.map) {
    const mp = m.map;
    const devLine = (d) => [
      d.ip, d.hostname, `— ${L.mapRisk[d.risk.level]}`, d.refs.length ? d.refs.join(', ') : '',
      d.risk.exploited ? 'CISA KEV' : '', d.isSelf ? `(${L.mapYou})` : '', d.ports.length ? `· ${L.mapPorts(d.ports.length)}` : '',
    ].filter(Boolean).join(' ');
    out.push('', h2('map'), '', L.mapIntro, '', '```');
    out.push(L.mapInternet);
    out.push(`└─ ${mp.gateway ? `${L.deviceTypes[mp.gateway.type] || L.deviceTypes.router}: ${devLine(mp.gateway)}${mp.gateway.synthetic ? ` (${L.mapGatewayNote})` : ''}` : L.mapNoGateway}`);
    mp.segments.forEach((sg, si) => {
      const lastS = si === mp.segments.length - 1;
      const pad = `   ${lastS ? '   ' : '│  '}`;
      out.push(`   ${lastS ? '└─' : '├─'} ${sg.other ? L.mapOther : `${L.mapLocalNet} ${sg.label}`} · ${L.mapDevices(sg.total)}`);
      sg.groups.forEach((g, gi) => {
        const lastG = gi === sg.groups.length - 1;
        out.push(`${pad}${lastG ? '└─' : '├─'} ${L.deviceTypes[g.type] || g.type} (${g.devices.length})`);
        g.devices.forEach((d, di) => out.push(`${pad}${lastG ? '  ' : '│ '}  ${di === g.devices.length - 1 ? '└─' : '├─'} ${devLine(d)}`));
      });
    });
    out.push('```', '');
  }

  out.push(h2('raw'), '');
  if (m.rawTruncated) out.push(`> ${L.rawTruncated(Math.round(m.rawLength / 1048576))}`, '');
  out.push('```', m.raw.replace(/```/g, "'''"), '```', '');
  out.push('---', `_${L.footer}${m.tester ? ` · ${m.tester}` : ''} · ${m.generatedAt}${m.intelMeta ? ` · ${L.dataSources(m.intelMeta.kevVersion)}` : ''}_`, '');
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
  critical: '#9b0018', high: '#d32f2f', medium: '#e67e00', low: '#9a7d00', safe: '#2e7d32', none: '#2e7d32',
};

export function toHtml(m) {
  const e = escapeHtml;
  const L = labels(m.lang);
  const t = (s) => tr(s, m.lang);
  const badge = (sev) =>
    `<span class="badge" style="background:${SEV_COLOR[sev] || '#555'}">${e((L.sev[sev] || sev).toUpperCase())}</span>`;
  const kevBadge = `<span class="badge kev">${e(L.colKev.toUpperCase())}</span>`;
  const sections = reportSections(m);
  const sec = Object.fromEntries(sections.map((s) => [s.id, s]));
  const h2 = (id) => `<h2 id="${id}"><span class="no">${sec[id].no}.</span> ${e(sec[id].title)}</h2>`;
  const c = m.counts;

  const cover = `
  <section class="cover">
    <div class="cover__brand">NMAP COMMAND BUILDER</div>
    <h1>${e(L.title)}</h1>
    <p class="cover__sub">${e(L.coverSubtitle)}</p>
    <table class="cover__meta">
      ${m.client ? `<tr><td>${e(L.preparedFor)}</td><td><b>${e(m.client)}</b></td></tr>` : ''}
      <tr><td>${e(L.targetsInScope)}</td><td><code>${e(m.target)}</code></td></tr>
      <tr><td>${e(L.preparedBy)}</td><td>${e([m.tester, m.organization].filter(Boolean).join(' · ') || L.notStated)}</td></tr>
      <tr><td>${e(L.scanWindow)}</td><td>${e(m.timestamp)}</td></tr>
      <tr><td>${e(L.reportDate)}</td><td>${e(m.generatedAt)}</td></tr>
      ${m.authorization ? `<tr><td>${e(L.authorization)}</td><td>${e(m.authorization)}</td></tr>` : ''}
    </table>
    <div class="cover__risk" style="border-color:${SEV_COLOR[m.risk]};color:${SEV_COLOR[m.risk]}">
      ${e(L.overallRisk)}: <b>${e((L.sev[m.risk] || m.risk).toUpperCase())}</b>
    </div>
    <div class="confidential">${e(L.confidential)}</div>
  </section>`;

  const toc = `
  <section class="toc">
    <h2>${e(L.contents)}</h2>
    <ol>${sections.map((s, i) => `<li><span class="toc__n">${i + 1}.</span>${e(s.title)}</li>`).join('')}</ol>
    <h3>${e(L.documentControl)}</h3>
    <table class="kv">
      ${detailRows(m, L).map(([k, v, code, dim]) => `<tr><td>${e(k)}</td><td>${code ? `<code>${e(v)}</code>` : dim ? `<span class="muted">${e(v)}</span>` : e(v)}</td></tr>`).join('')}
      <tr><td>${e(L.reportVersion)}</td><td>1.0</td></tr>
      <tr><td>${e(L.classification)}</td><td>${e(L.classificationValue)}</td></tr>
    </table>
  </section>`;

  const summary = `
  ${h2('summary')}
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
    <div class="card card--kev">${e(L.colKev)}<b>${m.exploitedCount}</b></div>
  </div>
  <h3>${e(L.priorityActions)}</h3>
  ${m.actions.length === 0 ? `<p class="muted">${e(L.noActions)}</p>` : `<ol class="actions">${m.actions.map((a) => `
    <li>${e(L.actionFix(t(a.title), a.host))} <span class="ref">${e(a.ref)}</span>
      — <b class="${a.exploited ? 'urgent' : ''}">${e(a.exploited ? L.actionExploited : `${L.colTimeframe.toLowerCase()} ${L.timeframe[a.timeframe]}`)}</b></li>`).join('')}</ol>`}`;

  const scope = `
  ${h2('scope')}
  <table class="kv">
    <tr><td>${e(L.targetsInScope)}</td><td><code>${e(m.target)}</code></td></tr>
    <tr><td>${e(L.scanWindow)}</td><td>${e(m.timestamp)}</td></tr>
    <tr><td>${e(L.tool)}</td><td>${e(m.nmapVersion || 'Nmap')} · Nmap Command Builder</td></tr>
    <tr><td>${e(L.command)}</td><td><code>${e(m.command)}</code></td></tr>
    ${m.authorization ? `<tr><td>${e(L.authorization)}</td><td>${e(m.authorization)}</td></tr>` : ''}
  </table>
  <h3>${e(L.techniques)}</h3>
  <ul>${m.techniques.map((x) => `<li>${e(x)}</li>`).join('')}</ul>
  <h3>${e(L.scopeTitle)}</h3>
  <p class="body">${e(L.scope)}</p>`;

  const rating = `
  <div class="keep">
  ${h2('rating')}
  <p class="body">${e(L.ratingIntro)}</p>
  <table>
    <thead><tr><th>${e(L.colSeverity)}</th><th>${e(L.colCvss)}</th><th>${e(L.colMeaning)}</th><th>${e(L.colTimeframe)}</th></tr></thead>
    <tbody>
      <tr><td>${kevBadge}</td><td>—</td><td>${e(L.exploitedNow)}. ${e(L.escalatedNote)}</td><td><b>${e(L.timeframe.exploited)}</b></td></tr>
      ${[['critical', '9.0–10.0'], ['high', '7.0–8.9'], ['medium', '4.0–6.9'], ['low', '0.1–3.9']].map(([s, r]) =>
    `<tr><td>${badge(s)}</td><td>${r}</td><td>${e(L.meaning[s])}</td><td>${e(L.timeframe[s])}</td></tr>`).join('')}
    </tbody>
  </table>
  </div>`;

  const overview = !sec.overview ? '' : `
  ${h2('overview')}
  <table>
    <thead><tr><th>${e(L.colId)}</th><th>${e(L.colSeverity)}</th><th>${e(L.colFinding)}</th><th>${e(L.colHost)}</th><th>${e(L.colKev)}</th><th class="num">${e(L.colEpss)}</th><th>${e(L.colDue)}</th></tr></thead>
    <tbody>${m.findings.map((f) => `
      <tr><td class="ref">${e(f.ref)}</td><td>${badge(f.severity)}</td><td>${e(t(f.title))}</td>
      <td>${e(f.host)}${f.port ? `<br><span class="muted">${e(f.port)}</span>` : ''}</td>
      <td>${f.exploited ? kevBadge : '—'}</td><td class="num">${e(epssText(f.epssMax))}</td><td>${e(L.timeframe[f.timeframe])}</td></tr>`).join('')}
    </tbody>
  </table>`;

  const findings = m.findings.length === 0
    ? `<p class="muted">${e(L.noFindings)}</p>`
    : m.findings.map((f) => `
      <div class="finding sev-${e(f.severity)}">
        <h3><span class="ref">${e(f.ref)}</span> ${badge(f.severity)} ${f.exploited ? kevBadge : ''} ${e(t(f.title))}</h3>
        ${f.exploited ? `<p class="kevnote">⚠ <b>${e(L.exploitedNow)}${f.ransomware ? ` — ${e(L.ransomwareUse)}` : ''}.</b> ${e(L.kevNote(f.kevDue))}${f.escalated ? ` ${e(L.escalatedNote)}` : ''}</p>` : ''}
        <table class="kv">
          <tr><td>${e(L.affectedAsset)}</td><td><b>${e(f.host)}</b>${f.port ? ` · ${e(L.port)} ${e(f.port)}` : ''}</td></tr>
          ${f.cvss != null ? `<tr><td>CVSS</td><td><b>${e(f.cvss)}</b>${f.vector ? ` <code>${e(f.vector)}</code>` : ''}</td></tr>` : ''}
          ${f.epssMax != null ? `<tr><td>EPSS</td><td>${e(epssText(f.epssMax))}</td></tr>` : ''}
          ${f.cwe.length ? `<tr><td>${e(L.weakness)}</td><td>${e(f.cwe.join(', '))}</td></tr>` : ''}
          <tr><td>${e(L.colTimeframe)}</td><td><b>${e(L.timeframe[f.timeframe])}</b></td></tr>
          <tr><td>${e(L.detectedBy)}</td><td><code>${e(f.script)}</code></td></tr>
          ${f.evidence ? `<tr><td>${e(L.evidence)}</td><td><code>${e(f.evidence)}</code></td></tr>` : ''}
        </table>
        <p class="label">${e(L.impact)}</p><p class="body">${e(L.impactText[f.severity])}</p>
        ${f.nvdDescription ? `<p class="label">${e(L.descriptionNvd)} — ${e(f.nvdDescriptionCve)}</p><p class="body">${e(f.nvdDescription)}</p>` : ''}
        ${f.cveDetails?.length ? `
        <p class="label">${e(L.relatedCves)}</p>
        <table class="cves"><thead><tr><th>${e(L.colCve)}</th><th class="num">CVSS</th><th class="num">EPSS</th><th>${e(L.colKev)}</th></tr></thead><tbody>
          ${f.cveDetails.slice(0, 12).map((x) => `<tr><td><code>${e(x.id)}</code></td><td class="num">${e(x.score ?? '—')}</td><td class="num">${e(epssText(x.epss))}</td><td>${x.kev ? kevBadge : '—'}</td></tr>`).join('')}
        </tbody></table>` : ''}
        <p class="label fix-title">${e(L.howToFix)}</p>
        <ol>${f.fix.map((s) => `<li>${e(t(s))}</li>`).join('')}</ol>
        ${f.refs?.length ? `<p class="refs">${f.refs.map((r) => e(r)).join('<br>')}</p>` : ''}
      </div>`).join('');

  const cmp = m.comparison;
  const comparison = !cmp ? '' : `
  ${h2('changes')}
  <p class="meta">${e(L.comparedWith(cmp.baselineTime, cmp.baselineCommand))}</p>
  ${cmp.sameCommand ? '' : `<p class="meta">⚠ ${e(L.differentCommand)}</p>`}
  ${cmp.sections.length === 0 ? `<p class="muted">${e(L.noChanges)}</p>` : cmp.sections.map((s) => `
    <div class="change change-${e(s.tone)}">
      <h3>${e(s.title)} (${s.items.length})</h3>
      <ul>${s.items.map((it) => `<li>${e(it)}</li>`).join('')}</ul>
    </div>`).join('')}`;

  const invLabel = (d) => getLabel(d.mac, d.ip, m.deviceLabels);
  const hasInvLabels = m.inventory && m.deviceLabels && m.inventory.some(invLabel);
  const inventory = !m.inventory ? '' : `
  ${h2('inventory')}
  <table>
    <thead><tr><th>${e(L.colIp)}</th><th>${e(L.colType)}</th>${hasInvLabels ? `<th>${e(L.colLabel || 'Label')}</th>` : ''}<th>${e(L.colName)}</th><th>${e(L.colMac)}</th><th>${e(L.colOpenPorts)}</th></tr></thead>
    <tbody>${m.inventory.map((d) => `
      <tr><td><b>${e(d.ip)}</b></td><td>${e(L.deviceTypes[d.type] || d.type)}</td>${hasInvLabels ? `<td>${e(invLabel(d) || '—')}</td>` : ''}<td>${e(d.hostname || '—')}${d.os ? `<br><span class="muted">${e(d.os)}</span>` : ''}</td>
      <td>${d.mac ? `<code>${e(d.mac)}</code>` : '—'}${(d.randomizedMac || d.vendor) ? `<br><span class="muted">${e(d.randomizedMac ? L.randomMac : d.vendor)}</span>` : ''}</td>
      <td>${e(d.ports.map((p) => p.port).join(', ') || '—')}</td></tr>`).join('')}
    </tbody>
  </table>`;

  const mapNode = (d, extra = '') => {
    const dl = getLabel(d.mac, d.ip, m.deviceLabels);
    const mapName = dl || d.hostname;
    return `
      <div class="nm-node nm-${e(d.risk.level)}">
        <div><b>${e(d.ip)}</b>${mapName ? ` <span class="nm-name${dl ? ' nm-label' : ''}">${e(mapName)}</span>` : ''}${extra}</div>
        <div class="nm-sub">${[
    e(L.mapRisk[d.risk.level]),
    d.refs.length ? `<b>${e(d.refs.join(', '))}</b>` : '',
    d.risk.exploited ? '<span class="nm-kev">CISA KEV</span>' : '',
    d.ports.length ? e(L.mapPorts(d.ports.length)) : '',
    d.isSelf ? `<i>${e(L.mapYou)}</i>` : '',
  ].filter(Boolean).join(' · ')}</div>
      </div>`;
  };
  const map = !m.map ? '' : `
  <section class="nm">
  ${h2('map')}
  <p class="muted">${e(L.mapIntro)}</p>
  <div class="nm-legend">${['critical', 'high', 'medium', 'exposed', 'ok'].filter((l) => m.map.counts[l] > 0 || l === 'ok')
    .map((l) => `<span class="nm-${l}"><i></i>${e(L.mapRisk[l])}: ${m.map.counts[l]}</span>`).join('')}</div>
  <div class="nm-spine">
    <div class="nm-cloud">${e(L.mapInternet)}</div><div class="nm-wire"></div>
    ${m.map.gateway ? `<div class="nm-gw"><div class="nm-gw__type">${e(L.deviceTypes[m.map.gateway.type] || L.deviceTypes.router)}</div>${mapNode(m.map.gateway, m.map.gateway.synthetic ? ` <span class="nm-name">(${e(L.mapGatewayNote)})</span>` : '')}</div>` : `<div class="nm-cloud">${e(L.mapNoGateway)}</div>`}
    <div class="nm-wire"></div>
  </div>
  ${m.map.segments.map((sg) => `
  <div class="nm-seg">
    <div class="nm-seg__label">${e(sg.other ? L.mapOther : `${L.mapLocalNet} ${sg.label}`)} · ${e(L.mapDevices(sg.total))}</div>
    <div class="nm-groups">${sg.groups.map((g) => `
      <div class="nm-group">
        <div class="nm-group__h">${e(L.deviceTypes[g.type] || g.type)} <span>${g.devices.length}</span></div>
        ${g.devices.map((d) => mapNode(d)).join('')}
      </div>`).join('')}
    </div>
  </div>`).join('')}
  </section>`;

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

  const advice = !sec.hardening ? '' : `${h2('hardening')}${m.portAdvice.map((a) => `
    <div class="advice">
      <h3>${e(L.colPort)} ${e(a.port)} — ${e(a.label)} ${badge(a.risk)}</h3>
      ${a.note ? `<p class="meta">${e(t(a.note))}</p>` : ''}
      <p class="meta">${e(L.affectedHosts)}: ${e(a.hosts.join(', '))}</p>
      <ul>${a.fixes.map((s) => `<li>${e(t(s))}</li>`).join('')}</ul>
    </div>`).join('')}`;

  const signoff = `
  ${h2('signoff')}
  <table class="sign">
    <thead><tr><th></th><th>${e(L.colName)}</th><th>${e(L.signDate)}</th><th>${e(L.signature)}</th></tr></thead>
    <tbody>
      <tr><td>${e(L.signPreparedBy)}</td><td>${e(m.tester)}</td><td>${e(m.generatedAt)}</td><td></td></tr>
      <tr><td>${e(L.signApprovedBy)}</td><td></td><td></td><td></td></tr>
    </tbody>
  </table>`;

  return `<!doctype html>
<html lang="${e(m.lang)}"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>${e(L.title)}</title>
<style>
  @page { size: A4; }
  body { font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; color: #1b1f1b; font-size: 10.2pt; line-height: 1.45; margin: 0; }
  h1 { font-size: 24pt; margin: 0 0 6px; color: #10351a; line-height: 1.15; }
  h2 { font-size: 14pt; border-bottom: 2px solid #1b5e20; padding-bottom: 3px; margin: 24px 0 8px; color: #10351a; page-break-after: avoid; }
  h2 .no { color: #6a8f6a; } h3 { font-size: 11pt; margin: 14px 0 4px; page-break-after: avoid; }
  code, pre { font-family: Menlo, Consolas, monospace; font-size: 8.6pt; }
  .meta { margin: 2px 0; color: #444; font-size: 9.6pt; } .muted { color: #777; font-style: italic; font-size: 9pt; }
  .body { margin: 2px 0 6px; } .label { font-weight: 700; margin: 8px 0 2px; color: #333; font-size: 9.5pt; }
  .cover { height: 245mm; display: flex; flex-direction: column; justify-content: center; page-break-after: always; }
  .cover__brand { font-family: Menlo, monospace; letter-spacing: 4px; color: #2e7d32; font-size: 9pt; margin-bottom: 18mm; }
  .cover__sub { font-size: 13pt; color: #444; margin: 0 0 14mm; }
  .cover__meta { border-collapse: collapse; width: auto; margin-bottom: 12mm; }
  .cover__meta td { border: none; padding: 3px 18px 3px 0; font-size: 11pt; vertical-align: top; } .cover__meta td:first-child { color: #666; }
  .cover__risk { display: inline-block; align-self: flex-start; border: 2px solid; border-radius: 6px; padding: 6px 14px; font-size: 13pt; margin-bottom: 12mm; }
  .keep { page-break-inside: avoid; }
  .nm { page-break-before: always; page-break-after: always; }
  .nm-legend { display: flex; flex-wrap: wrap; gap: 14px; font-size: 8.5pt; margin: 6px 0 10px; }
  .nm-legend i { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 5px; background: var(--c); vertical-align: middle; }
  .nm-spine { display: flex; flex-direction: column; align-items: center; }
  .nm-wire { width: 2px; height: 12px; background: #9aa89a; }
  .nm-cloud { border: 1px dashed #9aa89a; border-radius: 12px; padding: 3px 16px; font-size: 9pt; color: #444; }
  .nm-gw { width: 62mm; } .nm-gw__type { font-size: 7.5pt; text-transform: uppercase; letter-spacing: 1px; color: #666; text-align: center; margin-bottom: 2px; }
  .nm-seg { position: relative; border: 1px dashed #9aa89a; border-radius: 5px; padding: 16px 8px 8px; margin-top: 0; margin-bottom: 16px; }
  .nm-seg__label { position: absolute; top: -7px; left: 50%; transform: translateX(-50%); background: #fff; padding: 0 8px; font-size: 8pt; color: #555; white-space: nowrap; }
  .nm-groups { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; align-items: start; }
  .nm-group { border: 1px solid #d5ddd5; border-radius: 3px; padding: 5px; background: #fafcfa; }
  .nm-group__h { font-size: 7.5pt; text-transform: uppercase; letter-spacing: 1px; color: #10351a; font-weight: 700; margin-bottom: 4px; display: flex; page-break-after: avoid; }
  .nm-group__h span { margin-left: auto; color: #6a8f6a; }
  .nm-node { border: 1px solid #d5ddd5; border-left: 4px solid var(--c); background: #fff; padding: 3px 6px; margin-top: 4px; font-size: 8.5pt; page-break-inside: avoid; }
  .nm-node.nm-critical, .nm-node.nm-high { background: #fff4f2; }
  .nm-name { color: #555; } .nm-label { color: #0073aa; font-weight: 600; } .nm-sub { font-size: 7.5pt; color: #555; margin-top: 1px; }
  .nm-kev { color: #fff; background: #b71c1c; padding: 0 4px; border-radius: 2px; font-weight: 700; }
  .nm-critical { --c: #b71c1c; } .nm-high { --c: #e64a19; } .nm-medium { --c: #f57c00; } .nm-low, .nm-exposed { --c: #d4a600; } .nm-ok { --c: #2e7d32; }
  .toc { page-break-after: always; } .toc ol { font-size: 11pt; line-height: 1.9; list-style: none; margin-left: 0; } .toc__n { display: inline-block; min-width: 2.2em; }
  .confidential { border: 1px solid #9b0018; color: #9b0018; font-size: 8.5pt; font-weight: 700; padding: 5px 9px; }
  .kv { width: auto; border: none; margin: 4px 0; } .kv td { border: none; padding: 2px 16px 2px 0; font-size: 9.6pt; vertical-align: top; }
  .kv td:first-child { color: #666; white-space: nowrap; }
  .risk { display: flex; gap: 14px; align-items: center; border-radius: 6px; padding: 10px 14px; margin: 8px 0; color: #fff; page-break-inside: avoid; }
  .risk b { font-size: 15pt; white-space: nowrap; } .risk span { font-size: 10pt; }
  .summary { display: flex; gap: 6px; margin: 8px 0; }
  .card { border: 1px solid #ccc; border-radius: 6px; padding: 5px 8px; flex: 1; font-size: 8.5pt; color: #555; }
  .card b { display: block; font-size: 15pt; color: #1b1f1b; } .card--kev b { color: #9b0018; }
  .actions li { margin: 3px 0; } .urgent { color: #9b0018; } .ref { font-family: Menlo, monospace; font-size: 8.6pt; color: #555; white-space: nowrap; }
  .badge { color: #fff; border-radius: 3px; padding: 1px 6px; font-size: 7.6pt; font-weight: 700; letter-spacing: .5px; vertical-align: middle; white-space: nowrap; }
  .badge.kev { background: #000; color: #fff; border: 1px solid #9b0018; }
  .finding, .advice, .change { border-left: 4px solid #999; padding: 2px 0 6px 12px; margin: 12px 0; }
  .finding { page-break-inside: auto; } .finding h3 { page-break-after: avoid; }
  .kevnote { background: #fdecee; border: 1px solid #f3b6bf; padding: 5px 8px; margin: 4px 0 6px; font-size: 9.5pt; }
  .sev-critical { border-color: ${SEV_COLOR.critical}; } .sev-high { border-color: ${SEV_COLOR.high}; }
  .sev-medium { border-color: ${SEV_COLOR.medium}; } .sev-low { border-color: ${SEV_COLOR.low}; }
  .change-bad { border-color: ${SEV_COLOR.high}; } .change-good { border-color: ${SEV_COLOR.safe}; } .change-info { border-color: #0b57d0; }
  .fix-title { color: #1b5e20; }
  ol, ul { margin: 2px 0 4px 18px; padding: 0; } .refs { font-size: 8.2pt; color: #0b57d0; word-break: break-all; }
  table { border-collapse: collapse; width: 100%; font-size: 9.2pt; margin-bottom: 8px; }
  thead { display: table-header-group; } tr { page-break-inside: avoid; }
  th, td { border-bottom: 1px solid #ddd; padding: 4px 6px; text-align: left; vertical-align: top; } th { background: #eef4ee; } .num { text-align: right; }
  table.cves { width: auto; min-width: 60%; } table.cves td, table.cves th { padding: 2px 10px 2px 0; }
  table.sign td { height: 26px; } table.sign td:first-child { color: #666; white-space: nowrap; }
  pre { background: #f6f8f6; border: 1px solid #ddd; padding: 8px; white-space: pre-wrap; word-break: break-word; font-size: 7.8pt; }
  footer { margin-top: 20px; font-size: 8pt; color: #666; border-top: 1px solid #ddd; padding-top: 6px; }
</style></head>
<body>
  ${cover}
  ${toc}
  ${summary}
  ${scope}
  ${rating}
  ${overview}
  ${h2('findings')}
  ${findings}
  ${comparison}
  ${inventory}
  ${h2('ports')}
  ${hosts}
  ${advice}
  ${signoff}
  ${map}
  ${h2('raw')}
  ${m.rawTruncated ? `<p class="meta">⚠ ${e(L.rawTruncated(Math.round(m.rawLength / 1048576)))}</p>` : ''}
  <pre>${e(m.raw)}</pre>

  <footer>${e(L.footer)}${m.tester ? ` · ${e(m.tester)}` : ''} · ${e(m.generatedAt)}${m.intelMeta ? ` · ${e(L.dataSources(m.intelMeta.kevVersion))}` : ''}</footer>
</body></html>`;
}

/** Text pre patu kazdej strany PDF (cislo strany doplni Chromium). */
export function pdfFooterLabel(m) {
  const L = labels(m.lang);
  return { title: `${L.title} · ${L.classificationValue}`, page: L.page, tester: m.tester };
}

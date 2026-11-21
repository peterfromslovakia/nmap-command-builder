import React, { useState } from 'react';
import { useT } from '../i18n/ui';

const DNS_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'ALL'];

function useTool() {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  return { input, setInput, loading, setLoading, result, setResult, error, setError };
}

function ToolCard({ title, icon, children }) {
  return (
    <div className="tools-card">
      <div className="tools-card__title">{icon} {title}</div>
      {children}
    </div>
  );
}

function ToolOutput({ loading, error, children }) {
  if (loading) return <div className="tools-output tools-output--loading">…</div>;
  if (error) return <pre className="tools-output tools-output--error">{error}</pre>;
  if (!children) return null;
  return <div className="tools-output">{children}</div>;
}

// ─── WHOIS ────────────────────────────────────────────────────────────────────

function WhoisCard({ t }) {
  const { input, setInput, loading, setLoading, result, setResult, error, setError } = useTool();

  const run = async () => {
    if (!input.trim()) return;
    setLoading(true); setError(''); setResult(null);
    const r = await window.electronAPI.toolsWhois(input.trim());
    setLoading(false);
    if (r.error) setError(r.error);
    else setResult(r.output);
  };

  return (
    <ToolCard title={t('WHOIS')} icon="🔍">
      <div className="tools-row">
        <input className="tools-input" value={input} onChange={(e) => setInput(e.target.value)}
          placeholder="google.com / 8.8.8.8" onKeyDown={(e) => e.key === 'Enter' && run()} spellCheck={false} />
        <button className="btn btn--sm tools-run" onClick={run} disabled={loading || !input.trim()}>{t('Run')}</button>
      </div>
      <ToolOutput loading={loading} error={error}>
        {result && <pre className="tools-pre">{result}</pre>}
      </ToolOutput>
    </ToolCard>
  );
}

// ─── DNS lookup ───────────────────────────────────────────────────────────────

function DnsCard({ t }) {
  const { input, setInput, loading, setLoading, result, setResult, error, setError } = useTool();
  const [dnsType, setDnsType] = useState('A');

  const run = async () => {
    if (!input.trim()) return;
    setLoading(true); setError(''); setResult(null);
    const r = await window.electronAPI.toolsDns(input.trim(), dnsType);
    setLoading(false);
    if (r.error) setError(r.error);
    else setResult(r);
  };

  const formatDns = (r) => {
    if (r.type === 'ALL') {
      return r.results.map((item) => `${item.type}:\n${formatRecords(item)}`).join('\n\n');
    }
    return formatRecords(r);
  };

  const formatRecords = (item) => {
    if (!item.records || item.records.length === 0) return '  (none)';
    return item.records.map((rec) => {
      if (typeof rec === 'string') return `  ${rec}`;
      if (Array.isArray(rec)) return `  ${rec.join(' ')}`;
      return `  ${JSON.stringify(rec)}`;
    }).join('\n');
  };

  return (
    <ToolCard title={t('DNS Lookup')} icon="🌐">
      <div className="tools-row">
        <input className="tools-input" value={input} onChange={(e) => setInput(e.target.value)}
          placeholder="github.com" onKeyDown={(e) => e.key === 'Enter' && run()} spellCheck={false} />
        <select className="flag-select tools-type" value={dnsType} onChange={(e) => setDnsType(e.target.value)}
          aria-label={t('Record type')}>
          {DNS_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <button className="btn btn--sm tools-run" onClick={run} disabled={loading || !input.trim()}>{t('Run')}</button>
      </div>
      <ToolOutput loading={loading} error={error}>
        {result && <pre className="tools-pre">{formatDns(result)}</pre>}
      </ToolOutput>
    </ToolCard>
  );
}

// ─── SSL certifikát ──────────────────────────────────────────────────────────

function SslCard({ t }) {
  const { input, setInput, loading, setLoading, result, setResult, error, setError } = useTool();

  const run = async () => {
    if (!input.trim()) return;
    setLoading(true); setError(''); setResult(null);
    const [host, portStr] = input.trim().split(':');
    const r = await window.electronAPI.toolsSsl(host, Number(portStr) || 443);
    setLoading(false);
    if (r.error) setError(r.error);
    else setResult(r);
  };

  const daysColor = (n) => n < 0 ? 'tools-cert--expired' : n < 14 ? 'tools-cert--warn' : 'tools-cert--ok';

  return (
    <ToolCard title={t('SSL Certificate')} icon="🔒">
      <div className="tools-row">
        <input className="tools-input" value={input} onChange={(e) => setInput(e.target.value)}
          placeholder="github.com:443" onKeyDown={(e) => e.key === 'Enter' && run()} spellCheck={false} />
        <button className="btn btn--sm tools-run" onClick={run} disabled={loading || !input.trim()}>{t('Run')}</button>
      </div>
      <ToolOutput loading={loading} error={error}>
        {result && (
          <div className="tools-cert">
            <div className="tools-cert__row"><span className="tools-cert__k">Subject</span><span>{result.subject}</span></div>
            <div className="tools-cert__row"><span className="tools-cert__k">Issuer</span><span>{result.issuer}</span></div>
            <div className="tools-cert__row"><span className="tools-cert__k">Valid from</span><span>{result.validFrom}</span></div>
            <div className="tools-cert__row"><span className="tools-cert__k">Valid to</span><span>{result.validTo}</span></div>
            <div className="tools-cert__row"><span className="tools-cert__k">Days left</span>
              <span className={daysColor(result.daysLeft)}>{result.expired ? `EXPIRED ${Math.abs(result.daysLeft)}d ago` : `${result.daysLeft}d`}</span>
            </div>
            {result.sans && result.sans !== '—' && (
              <div className="tools-cert__row"><span className="tools-cert__k">SANs</span><span className="tools-cert__sans">{result.sans}</span></div>
            )}
            <div className="tools-cert__row"><span className="tools-cert__k">SHA-256</span><span className="tools-cert__fp">{result.fingerprint}</span></div>
          </div>
        )}
      </ToolOutput>
    </ToolCard>
  );
}

// ─── IP informácie (ipinfo.io) ────────────────────────────────────────────────

function IpInfoCard({ t }) {
  const { input, setInput, loading, setLoading, result, setResult, error, setError } = useTool();

  const run = async () => {
    if (!input.trim()) return;
    setLoading(true); setError(''); setResult(null);
    const r = await window.electronAPI.toolsIpinfo(input.trim());
    setLoading(false);
    if (r.error) setError(r.error);
    else setResult(r);
  };

  const rows = result ? [
    ['IP', result.ip],
    ['Hostname', result.hostname],
    ['Organisation', result.org],
    ['Country', result.country],
    ['Region', result.region],
    ['City', result.city],
    ['Location', result.loc],
    ['Timezone', result.timezone],
  ].filter(([, v]) => v) : [];

  return (
    <ToolCard title={t('IP Information')} icon="📍">
      <div className="tools-row">
        <input className="tools-input" value={input} onChange={(e) => setInput(e.target.value)}
          placeholder="8.8.8.8" onKeyDown={(e) => e.key === 'Enter' && run()} spellCheck={false} />
        <button className="btn btn--sm tools-run" onClick={run} disabled={loading || !input.trim()}>{t('Run')}</button>
      </div>
      <ToolOutput loading={loading} error={error}>
        {result && (
          <div className="tools-cert">
            {rows.map(([k, v]) => (
              <div key={k} className="tools-cert__row">
                <span className="tools-cert__k">{k}</span><span>{v}</span>
              </div>
            ))}
          </div>
        )}
      </ToolOutput>
    </ToolCard>
  );
}

// ─── Hlavná záložka ───────────────────────────────────────────────────────────

export default function ToolsTab() {
  const t = useT();
  return (
    <div className="tools-tab">
      <div className="tools-grid">
        <WhoisCard t={t} />
        <DnsCard t={t} />
        <SslCard t={t} />
        <IpInfoCard t={t} />
      </div>
    </div>
  );
}

import React, { useMemo, useState, useCallback } from 'react';
import { parseScanSummary } from '../utils/commandBuilder';
import { getPortRisk } from '../data/portRisk';
import { getPortIntel } from '../data/portIntel';

const RISK_CSS = {
  high:   'port-risk-high',
  medium: 'port-risk-medium',
  safe:   'port-risk-safe',
};

export default function PortsPanel({ lines, scanStatus, onLoadCommand }) {
  const { openPorts } = useMemo(() => parseScanSummary(lines), [lines]);

  const [selectedPort, setSelectedPort] = useState(null);
  const [copied, setCopied] = useState(false);
  const [copiedActionIdx, setCopiedActionIdx] = useState(null);

  const togglePort = useCallback((port) => {
    setSelectedPort((prev) => (prev === port ? null : port));
  }, []);

  const handleCopyList = useCallback(() => {
    const list = openPorts.map((p) => p.port).join(',');
    navigator.clipboard.writeText(list).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    });
  }, [openPorts]);

  const handleCopyAction = useCallback((cmd, idx) => {
    navigator.clipboard.writeText(cmd).then(() => {
      setCopiedActionIdx(idx);
      setTimeout(() => setCopiedActionIdx(null), 1600);
    });
  }, []);

  if (scanStatus !== 'done' && scanStatus !== 'killed') return null;
  if (!openPorts.length) return null;

  return (
    <div className="ports-panel">
      <div className="ports-panel__header">
        <span className="ports-panel__title">OPEN PORTS</span>
        <div className="ports-panel__header-actions">
          <span className="ports-panel__count">{openPorts.length} open</span>
          <button
            className={`btn btn--xs btn--copy ${copied ? 'btn--copied' : ''}`}
            onClick={handleCopyList}
            title="Copy port list (e.g. 22,80,443)"
          >
            {copied ? '✓ COPIED' : '⎘ COPY LIST'}
          </button>
        </div>
      </div>
      <div className="ports-panel__body">
        <table className="ports-table">
          <thead>
            <tr>
              <th className="ports-th ports-th--risk"></th>
              <th className="ports-th">PORT</th>
              <th className="ports-th">PROTO</th>
              <th className="ports-th">SERVICE</th>
              <th className="ports-th ports-th--version">VERSION</th>
            </tr>
          </thead>
          <tbody>
            {openPorts.map((p, i) => {
              const risk    = getPortRisk(p.port);
              const intel   = getPortIntel(p.port);
              const isOpen  = selectedPort === p.port;
              const riskCss = RISK_CSS[risk] || '';

              return (
                <React.Fragment key={i}>
                  <tr
                    className={`ports-row ${riskCss} ${intel ? 'ports-row--clickable' : ''} ${isOpen ? 'ports-row--active' : ''}`}
                    onClick={intel ? () => togglePort(p.port) : undefined}
                    title={intel ? 'Click to see follow-up actions' : undefined}
                  >
                    <td className="ports-cell ports-cell--risk">
                      <span className={`port-risk-dot port-risk-dot--${risk}`} />
                    </td>
                    <td className="ports-cell ports-cell--port">
                      {p.port}
                      {intel && (
                        <span className="ports-chevron">{isOpen ? ' ▾' : ' ▸'}</span>
                      )}
                    </td>
                    <td className="ports-cell ports-cell--proto">{p.proto}</td>
                    <td className="ports-cell ports-cell--service">{p.service || '—'}</td>
                    <td className="ports-cell ports-cell--version">{p.version || '—'}</td>
                  </tr>

                  {isOpen && intel && (
                    <tr className="ports-row ports-row--actions-row">
                      <td colSpan={5} className="ports-cell--actions">
                        <div className="port-actions">
                          <div className="port-actions__header">
                            <span className="port-actions__label">{intel.label}</span>
                            <span className={`port-actions__risk port-actions__risk--${risk}`}>
                              {risk.toUpperCase()}
                            </span>
                          </div>
                          <p className="port-actions__risk-note">{intel.risk}</p>
                          <div className="port-actions__cmds">
                            {intel.followUp.map((fu, j) => (
                              <div key={j} className="port-action-row">
                                <code className="port-action-row__cmd">{fu.cmd}</code>
                                <div className="port-action-row__btns">
                                  <button
                                    className={`btn btn--xs btn--copy ${copiedActionIdx === `${i}-${j}` ? 'btn--copied' : ''}`}
                                    onClick={(e) => { e.stopPropagation(); handleCopyAction(fu.cmd, `${i}-${j}`); }}
                                    title="Copy command"
                                  >
                                    {copiedActionIdx === `${i}-${j}` ? '✓' : '⎘'}
                                  </button>
                                  {onLoadCommand && (
                                    <button
                                      className="btn btn--xs btn--ghost"
                                      onClick={(e) => { e.stopPropagation(); onLoadCommand(fu.cmd); }}
                                      title="Load into builder"
                                    >
                                      ↗
                                    </button>
                                  )}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

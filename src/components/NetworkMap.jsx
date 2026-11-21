import React, { useMemo, useState } from 'react';
import { DEVICE_TYPES } from '../utils/inventory';
import { buildTopology, hostIp } from '../utils/topology';
import { getPortRisk } from '../data/portRisk';
import { getLabel } from '../utils/deviceLabels';
import { useLang } from '../i18n/ui';
import { tr } from '../i18n/report';

const GROUP_LIMIT = 24;
const RISK_LABEL = {
  critical: 'critical vulnerability',
  high: 'high-risk vulnerability',
  medium: 'medium vulnerability',
  low: 'low vulnerability',
  exposed: 'risky open ports',
  ok: 'nothing found',
};
const LEGEND = ['critical', 'high', 'medium', 'exposed', 'ok'];
const SEV_LABEL = { critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW' };

function DeviceNode({ d, selected, onSelect, t, labels }) {
  const type = DEVICE_TYPES[d.type] || DEVICE_TYPES.unknown;
  const customLabel = getLabel(d.mac, d.ip, labels);
  const name = customLabel || d.hostname || (d.randomizedMac ? '' : d.vendor);
  return (
    <button
      type="button"
      className={`tmap-node tmap-node--${d.risk.level}${selected ? ' tmap-node--sel' : ''}${d.isSelf ? ' tmap-node--self' : ''}`}
      onClick={() => onSelect(selected ? null : d.ip)}
      title={`${d.ip}${name ? ` · ${name}` : ''} · ${t(type.label)} · ${t(RISK_LABEL[d.risk.level])}`}
    >
      <span className="tmap-node__icon">{type.icon}</span>
      <span className="tmap-node__main">
        <span className="tmap-node__ip">{d.ip}</span>
        {name && <span className={`tmap-node__name${customLabel ? ' tmap-node__name--label' : ''}`}>{name}</span>}
      </span>
      <span className="tmap-node__tags">
        {d.isSelf && <span className="tmap-tag tmap-tag--self">{t('YOU')}</span>}
        {d.risk.exploited && <span className="tmap-tag tmap-tag--kev" title={t('Actively exploited (CISA KEV)')}>KEV</span>}
        {d.risk.findings > 0 && <span className="tmap-tag tmap-tag--vuln">{d.risk.findings}</span>}
        {d.ports.length > 0 && <span className="tmap-tag" title={t('{n} open ports', { n: d.ports.length })}>{d.ports.length}p</span>}
      </span>
    </button>
  );
}

function Detail({ d, findings, onScanDevice, onClose, t, lang, labels }) {
  const type = DEVICE_TYPES[d.type] || DEVICE_TYPES.unknown;
  const own = findings.filter((f) => hostIp(f.host) === d.ip);
  const customLabel = getLabel(d.mac, d.ip, labels);
  return (
    <div className={`tmap-detail tmap-detail--${d.risk.level}`}>
      <div className="tmap-detail__head">
        <span className="tmap-detail__icon">{type.icon}</span>
        <span className="tmap-detail__ip">{d.ip}</span>
        {customLabel && <span className="tmap-detail__name tmap-detail__name--label">{customLabel}</span>}
        {d.hostname && d.hostname !== customLabel && <span className="tmap-detail__name">{d.hostname}</span>}
        <span className="tmap-detail__type">{t(type.label)}</span>
        <span className="tmap-detail__risk">{t(RISK_LABEL[d.risk.level])}</span>
        <span className="tmap-detail__actions">
          {onScanDevice && !d.synthetic && <button className="btn btn--xs" onClick={() => onScanDevice(d.ip)}>{t('SCAN ›')}</button>}
          <button className="link-btn" onClick={onClose} aria-label={t('close')}>✕</button>
        </span>
      </div>
      <div className="tmap-detail__grid">
        {d.synthetic && <div className="tmap-detail__note">{t('Default gateway of this computer — it did not answer the scan.')}</div>}
        {(d.mac || d.vendor) && (
          <div><span className="tmap-detail__k">MAC</span>{d.mac || '—'}{' '}
            <span className="tmap-detail__dim">{d.randomizedMac ? t('private (randomised) MAC') : d.vendor}</span>
          </div>
        )}
        {d.os && <div><span className="tmap-detail__k">{t('OS')}</span>{d.os}</div>}
        {d.latencyMs != null && <div><span className="tmap-detail__k">{t('Latency')}</span>{d.latencyMs} ms</div>}
      </div>
      {d.ports.length > 0 && (
        <div className="tmap-detail__ports">
          {d.ports.map((p) => (
            <span key={`${p.port}/${p.proto}`} className={`tmap-port tmap-port--${getPortRisk(p.port) || 'safe'}`} title={p.version}>
              {p.port}/{p.proto} <b>{p.service}</b>
            </span>
          ))}
        </div>
      )}
      {own.length > 0 && (
        <ul className="tmap-detail__findings">
          {own.map((f, i) => (
            <li key={i}><span className={`sev-badge sev-badge--${f.severity}`}>{t(SEV_LABEL[f.severity])}</span> {tr(f.title, lang)}{f.port ? <span className="tmap-detail__dim"> · {f.port}</span> : null}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Mapa siete: internet → router → skupiny zariadeni podla typu, farba podla rizika. */
export default function NetworkMap({ devices, findings = [], gatewayIp, localIps, target, onScanDevice, labels }) {
  const { t, lang } = useLang();
  const [selected, setSelected] = useState(null);
  const [onlyRisky, setOnlyRisky] = useState(false);
  const [expanded, setExpanded] = useState({});

  const topo = useMemo(() => buildTopology({ devices, gatewayIp, localIps, findings, target }), [devices, gatewayIp, localIps, findings, target]);
  const risky = (d) => d.risk.level !== 'ok';
  const filterGroups = (groups) => groups
    .map((g) => ({ ...g, devices: onlyRisky ? g.devices.filter(risky) : g.devices }))
    .filter((g) => g.devices.length > 0);
  const segments = topo.segments.map((sg) => ({ ...sg, groups: filterGroups(sg.groups) }));
  const all = [topo.gateway, ...topo.groups.flatMap((g) => g.devices)].filter(Boolean);
  const sel = all.find((d) => d.ip === selected) || null;
  const riskyCount = all.filter(risky).length;

  return (
    <div className="tmap">
      <div className="intel-panel__header">
        <span className="tmap__title">{t('NETWORK MAP')}</span>
        <span className="tmap__target">{target}</span>
        <span className="tmap__count">{t('{n} devices', { n: topo.total })}</span>
        <span className="tmap__legend">
          {LEGEND.filter((l) => topo.counts[l] > 0 || l === 'ok').map((l) => (
            <span key={l} className={`tmap-legend tmap-legend--${l}`}><i />{t(RISK_LABEL[l])} {topo.counts[l] || 0}</span>
          ))}
        </span>
        {riskyCount > 0 && (
          <label className="tmap__filter">
            <input type="checkbox" checked={onlyRisky} onChange={(e) => setOnlyRisky(e.target.checked)} />
            {t('only devices at risk')}
          </label>
        )}
      </div>

      <div className="tmap__body">
        <div className="tmap__spine">
          <div className="tmap-cloud">☁ {t('Internet')}</div>
          <div className="tmap__wire" />
          {topo.gateway ? (
            <DeviceNode d={topo.gateway} selected={selected === topo.gateway.ip} onSelect={setSelected} t={t} labels={labels} />
          ) : (
            <div className="tmap-cloud tmap-cloud--net" title={t('The router was not found in this scan')}>⇄ {target}</div>
          )}
          <div className="tmap__wire" />
        </div>

        <div className="tmap__segments">
          {segments.map((sg, si) => (
            <div key={sg.label || `other-${si}`} className="tmap__groups">
              <span className="tmap__segment">
                {sg.other ? t('Other addresses') : `${t('Local network')} ${sg.label}`} · {t('{n} devices', { n: sg.total })}
              </span>
              {sg.groups.map((g) => {
                const type = DEVICE_TYPES[g.type] || DEVICE_TYPES.unknown;
                const key = `${si}:${g.type}`;
                const open = expanded[key] || g.devices.length <= GROUP_LIMIT;
                const list = open ? g.devices : g.devices.slice(0, GROUP_LIMIT);
                return (
                  <div key={g.type} className="tmap-group">
                    <div className="tmap-group__head">
                      <span className="tmap-group__icon">{type.icon}</span>
                      {t(type.label)} <span className="tmap-group__n">{g.devices.length}</span>
                    </div>
                    <div className="tmap-group__list">
                      {list.map((d) => <DeviceNode key={d.ip} d={d} selected={selected === d.ip} onSelect={setSelected} t={t} labels={labels} />)}
                      {!open && (
                        <button className="link-btn tmap-group__more" onClick={() => setExpanded((e) => ({ ...e, [key]: true }))}>
                          {t('+ {n} more', { n: g.devices.length - GROUP_LIMIT })}
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
              {sg.groups.length === 0 && <div className="tmap__empty">{t('No device at risk was found.')}</div>}
            </div>
          ))}
        </div>
      </div>

      {sel && <Detail d={sel} findings={findings} onScanDevice={onScanDevice} onClose={() => setSelected(null)} t={t} lang={lang} labels={labels} />}
      <div className="tmap__hint">
        {t('Click a device for details. The layout is logical (devices grouped by type behind the router), not the physical cabling.')}
      </div>
    </div>
  );
}

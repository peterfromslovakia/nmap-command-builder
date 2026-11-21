import React, { useMemo, useState, useRef } from 'react';
import { DEVICE_TYPES, ipNum } from '../utils/inventory';
import { getLabel } from '../utils/deviceLabels';
import { useT } from '../i18n/ui';

const SORTS = {
  ip: (a, b) => ipNum(a.ip) - ipNum(b.ip),
  type: (a, b) => a.type.localeCompare(b.type) || ipNum(a.ip) - ipNum(b.ip),
  ports: (a, b) => b.ports.length - a.ports.length || ipNum(a.ip) - ipNum(b.ip),
  vendor: (a, b) => (a.vendor || '~').localeCompare(b.vendor || '~') || ipNum(a.ip) - ipNum(b.ip),
};

/** Inventar zariadeni v sieti (po "SCAN NETWORK" alebo skene viacerych hostov). */
export default function InventoryPanel({ devices, target, onScanDevice, onExportCsv, onFindMacs, labels, onLabelChange }) {
  const t = useT();
  const label = (type) => t(DEVICE_TYPES[type].label);
  const [query, setQuery] = useState('');
  const [sort, setSort] = useState('ip');
  const [editingIp, setEditingIp] = useState(null);
  const [editValue, setEditValue] = useState('');
  const editRef = useRef(null);

  const counts = useMemo(() => {
    const c = {};
    devices.forEach((d) => { c[d.type] = (c[d.type] || 0) + 1; });
    return Object.entries(c).sort((a, b) => b[1] - a[1]);
  }, [devices]);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = q
      ? devices.filter((d) => [d.ip, d.hostname, d.mac, d.vendor, d.os, DEVICE_TYPES[d.type].label, label(d.type),
          getLabel(d.mac, d.ip, labels),
          ...d.ports.map((p) => `${p.port} ${p.service} ${p.version}`)].join(' ').toLowerCase().includes(q))
      : devices;
    return [...list].sort(SORTS[sort]);
  }, [devices, query, sort, labels]); // eslint-disable-line react-hooks/exhaustive-deps -- label zavisi len od jazyka

  const withPorts = devices.some((d) => d.ports.length > 0);

  const startEdit = (d) => {
    setEditingIp(d.ip);
    setEditValue(getLabel(d.mac, d.ip, labels));
    setTimeout(() => editRef.current && editRef.current.focus(), 0);
  };
  const commitEdit = (d) => {
    if (onLabelChange) onLabelChange(d.mac, d.ip, editValue.trim());
    setEditingIp(null);
  };
  const cancelEdit = () => setEditingIp(null);

  return (
    <div className="inventory-panel">
      <div className="intel-panel__header">
        <span className="inventory-panel__title">{t('NETWORK DEVICES')}</span>
        <span className="inventory-panel__target">{target}</span>
        <div className="intel-panel__summary">
          <span className="inventory-count">{devices.length} {devices.length === 1 ? t('device') : t('devices')}</span>
          <button className="findings-export" onClick={onExportCsv} title={t('Save the device list as CSV (Excel)')}>↓ CSV</button>
        </div>
      </div>

      {onFindMacs && devices.length > 0 && devices.every((d) => !d.mac) && (
        <div className="inventory-machint">
          <span>ⓘ {t('MAC addresses and vendors were not available — the system hides them from apps without administrator rights.')} {t('An administrator scan (ARP) also finds sleeping phones.')}</span>
          <button className="btn btn--xs noroot-notice__btn" onClick={onFindMacs}>🔒 {t('FIND MAC ADDRESSES (administrator)')}</button>
        </div>
      )}

      <div className="inventory-types">
        {counts.map(([type, n]) => (
          <button key={type} className="inventory-type" onClick={() => setQuery(label(type))} title={t('Filter')}>
            <span className="inventory-type__icon">{DEVICE_TYPES[type].icon}</span> {label(type)} <b>{n}</b>
          </button>
        ))}
        <span className="inventory-tools">
          <input className="search-input inventory-search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t('Filter: IP, name, vendor, port…')} spellCheck={false} />
          {query && <button className="link-btn" onClick={() => setQuery('')}>{t('clear')}</button>}
          <select className="flag-select inventory-sort" value={sort} onChange={(e) => setSort(e.target.value)} aria-label={t('Sort devices')}>
            <option value="ip">{t('sort: IP')}</option>
            <option value="type">{t('sort: type')}</option>
            <option value="vendor">{t('sort: vendor')}</option>
            <option value="ports">{t('sort: open ports')}</option>
          </select>
        </span>
      </div>

      <div className="inventory-table-wrap">
        <table className="inventory-table">
          <thead>
            <tr>
              <th>{t('TYPE')}</th><th>{t('IP ADDRESS')}</th><th>{t('NAME')}</th><th>{t('MAC / VENDOR')}</th>
              {withPorts && <th>{t('OPEN PORTS')}</th>}
              <th className="num">{t('LATENCY')}</th><th />
            </tr>
          </thead>
          <tbody>
            {shown.map((d) => (
              <tr key={d.ip}>
                <td className="inv-type" title={label(d.type)}>
                  <span className={`inv-type__icon inv-type--${d.type}`}>{DEVICE_TYPES[d.type].icon}</span>
                  <span className="inv-type__label">{label(d.type)}</span>
                </td>
                <td className="inv-ip">{d.ip}</td>
                <td className="inv-name">
                  {editingIp === d.ip ? (
                    <input
                      ref={editRef}
                      className="inv-label-edit"
                      value={editValue}
                      onChange={(e) => setEditValue(e.target.value)}
                      onKeyDown={(e) => { if (e.key === 'Enter') commitEdit(d); if (e.key === 'Escape') cancelEdit(); }}
                      onBlur={() => commitEdit(d)}
                      placeholder={d.hostname || d.ip}
                      maxLength={60}
                    />
                  ) : (
                    <>
                      {getLabel(d.mac, d.ip, labels)
                        ? <span className="inv-label">{getLabel(d.mac, d.ip, labels)}</span>
                        : (d.hostname || <span className="inv-dim">—</span>)}
                      {onLabelChange && (
                        <button className="inv-edit-btn" onClick={() => startEdit(d)} title={t('Edit device label')}>✏</button>
                      )}
                      {getLabel(d.mac, d.ip, labels) && d.hostname && (
                        <span className="inv-os">{d.hostname}</span>
                      )}
                      {d.os && <span className="inv-os">{d.os}</span>}
                    </>
                  )}
                </td>
                <td className="inv-mac">
                  {d.mac ? <code>{d.mac}</code> : <span className="inv-dim">—</span>}
                  <span className="inv-vendor">{d.randomizedMac ? t('private (randomised) MAC') : d.vendor}</span>
                </td>
                {withPorts && (
                  <td className="inv-ports">
                    {d.ports.length === 0 ? <span className="inv-dim">{t('none')}</span> : d.ports.map((p) => (
                      <span key={`${p.port}/${p.proto}`} className="inv-port" title={`${p.service} ${p.version}`.trim()}>{p.port}</span>
                    ))}
                  </td>
                )}
                <td className="num inv-dim">{d.latencyMs != null ? `${d.latencyMs} ms` : ''}</td>
                <td><button className="btn btn--xs" onClick={() => onScanDevice(d.ip)} title={t('Use this device as the target and pick a scan')}>{t('SCAN')} ›</button></td>
              </tr>
            ))}
          </tbody>
        </table>
        {shown.length === 0 && <div className="findings-empty">{t('No device matches')} “{query}”.</div>}
      </div>
      <div className="inventory-note">
        {t("Device type is an estimate from open ports, network card vendor and name. MAC addresses come from this computer's ARP table and are available only for devices in the same local network.")}
      </div>
    </div>
  );
}

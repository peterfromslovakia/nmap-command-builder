import React, { useMemo, useState } from 'react';
import { DEVICE_TYPES, ipNum } from '../utils/inventory';

const SORTS = {
  ip: (a, b) => ipNum(a.ip) - ipNum(b.ip),
  type: (a, b) => a.type.localeCompare(b.type) || ipNum(a.ip) - ipNum(b.ip),
  ports: (a, b) => b.ports.length - a.ports.length || ipNum(a.ip) - ipNum(b.ip),
  vendor: (a, b) => (a.vendor || '~').localeCompare(b.vendor || '~') || ipNum(a.ip) - ipNum(b.ip),
};

/** Inventar zariadeni v sieti (po "SCAN NETWORK" alebo skene viacerych hostov). */
export default function InventoryPanel({ devices, target, onScanDevice, onExportCsv }) {
  const [query, setQuery] = useState('');
  const [sort, setSort] = useState('ip');

  const counts = useMemo(() => {
    const c = {};
    devices.forEach((d) => { c[d.type] = (c[d.type] || 0) + 1; });
    return Object.entries(c).sort((a, b) => b[1] - a[1]);
  }, [devices]);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = q
      ? devices.filter((d) => [d.ip, d.hostname, d.mac, d.vendor, d.os, DEVICE_TYPES[d.type].label,
        ...d.ports.map((p) => `${p.port} ${p.service} ${p.version}`)].join(' ').toLowerCase().includes(q))
      : devices;
    return [...list].sort(SORTS[sort]);
  }, [devices, query, sort]);

  const withPorts = devices.some((d) => d.ports.length > 0);

  return (
    <div className="inventory-panel">
      <div className="intel-panel__header">
        <span className="inventory-panel__title">NETWORK DEVICES</span>
        <span className="inventory-panel__target">{target}</span>
        <div className="intel-panel__summary">
          <span className="inventory-count">{devices.length} device{devices.length === 1 ? '' : 's'}</span>
          <button className="findings-export" onClick={onExportCsv} title="Save the device list as CSV (Excel)">↓ CSV</button>
        </div>
      </div>

      <div className="inventory-types">
        {counts.map(([type, n]) => (
          <button key={type} className="inventory-type" onClick={() => setQuery(DEVICE_TYPES[type].label)} title="Filter">
            <span className="inventory-type__icon">{DEVICE_TYPES[type].icon}</span> {DEVICE_TYPES[type].label} <b>{n}</b>
          </button>
        ))}
        <span className="inventory-tools">
          <input className="search-input inventory-search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter: IP, name, vendor, port…" spellCheck={false} />
          {query && <button className="link-btn" onClick={() => setQuery('')}>clear</button>}
          <select className="flag-select inventory-sort" value={sort} onChange={(e) => setSort(e.target.value)} aria-label="Sort devices">
            <option value="ip">sort: IP</option>
            <option value="type">sort: type</option>
            <option value="vendor">sort: vendor</option>
            <option value="ports">sort: open ports</option>
          </select>
        </span>
      </div>

      <div className="inventory-table-wrap">
        <table className="inventory-table">
          <thead>
            <tr>
              <th>TYPE</th><th>IP ADDRESS</th><th>NAME</th><th>MAC / VENDOR</th>
              {withPorts && <th>OPEN PORTS</th>}
              <th className="num">LATENCY</th><th />
            </tr>
          </thead>
          <tbody>
            {shown.map((d) => (
              <tr key={d.ip}>
                <td className="inv-type" title={DEVICE_TYPES[d.type].label}>
                  <span className={`inv-type__icon inv-type--${d.type}`}>{DEVICE_TYPES[d.type].icon}</span>
                  <span className="inv-type__label">{DEVICE_TYPES[d.type].label}</span>
                </td>
                <td className="inv-ip">{d.ip}</td>
                <td className="inv-name">{d.hostname || '—'}{d.os && <span className="inv-os">{d.os}</span>}</td>
                <td className="inv-mac">
                  {d.mac ? <code>{d.mac}</code> : <span className="inv-dim">—</span>}
                  <span className="inv-vendor">{d.randomizedMac ? 'private (randomised) MAC' : d.vendor}</span>
                </td>
                {withPorts && (
                  <td className="inv-ports">
                    {d.ports.length === 0 ? <span className="inv-dim">none</span> : d.ports.map((p) => (
                      <span key={`${p.port}/${p.proto}`} className="inv-port" title={`${p.service} ${p.version}`.trim()}>{p.port}</span>
                    ))}
                  </td>
                )}
                <td className="num inv-dim">{d.latencyMs != null ? `${d.latencyMs} ms` : ''}</td>
                <td><button className="btn btn--xs" onClick={() => onScanDevice(d.ip)} title="Use this device as the target and pick a scan">SCAN ›</button></td>
              </tr>
            ))}
          </tbody>
        </table>
        {shown.length === 0 && <div className="findings-empty">No device matches “{query}”.</div>}
      </div>
      <div className="inventory-note">
        Device type is an estimate from open ports, network card vendor and name. MAC addresses come from this
        computer&apos;s ARP table and are available only for devices in the same local network.
      </div>
    </div>
  );
}

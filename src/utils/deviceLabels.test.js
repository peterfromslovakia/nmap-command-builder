import { getLabel, setLabel, loadLabels, saveLabels } from './deviceLabels';

const MAC = 'AA:BB:CC:DD:EE:FF';
const IP  = '192.168.1.5';

describe('getLabel', () => {
  it('returns empty string when no labels', () => {
    expect(getLabel(MAC, IP, null)).toBe('');
    expect(getLabel(MAC, IP, { byMac: {}, byIp: {} })).toBe('');
  });

  it('returns MAC label when both exist', () => {
    const labels = { byMac: { [MAC]: 'Môj NAS' }, byIp: { [IP]: 'Iné' } };
    expect(getLabel(MAC, IP, labels)).toBe('Môj NAS');
  });

  it('falls back to IP when no MAC', () => {
    const labels = { byMac: {}, byIp: { [IP]: 'Router' } };
    expect(getLabel('', IP, labels)).toBe('Router');
    expect(getLabel(null, IP, labels)).toBe('Router');
  });

  it('returns empty string when MAC not found and no IP', () => {
    const labels = { byMac: {}, byIp: {} };
    expect(getLabel(MAC, IP, labels)).toBe('');
  });
});

describe('setLabel', () => {
  it('sets label by MAC when MAC present', () => {
    const result = setLabel(MAC, IP, 'Kamera', { byMac: {}, byIp: {} });
    expect(result.byMac[MAC]).toBe('Kamera');
    expect(result.byIp[IP]).toBeUndefined();
  });

  it('sets label by IP when no MAC', () => {
    const result = setLabel('', IP, 'Tlačiareň', { byMac: {}, byIp: {} });
    expect(result.byIp[IP]).toBe('Tlačiareň');
  });

  it('removes label when name is empty string', () => {
    const labels = { byMac: { [MAC]: 'Stará' }, byIp: {} };
    const result = setLabel(MAC, IP, '', labels);
    expect(result.byMac[MAC]).toBeUndefined();
  });

  it('is immutable — original unchanged', () => {
    const orig = { byMac: {}, byIp: {} };
    setLabel(MAC, IP, 'Test', orig);
    expect(orig.byMac[MAC]).toBeUndefined();
  });

  it('works with null labels', () => {
    const result = setLabel(MAC, IP, 'Init', null);
    expect(result.byMac[MAC]).toBe('Init');
  });
});

describe('loadLabels', () => {
  it('returns empty objects when localStorage empty', () => {
    const result = loadLabels();
    expect(result).toEqual({ byMac: {}, byIp: {} });
  });

  it('round-trips through saveLabels + loadLabels', () => {
    const labels = { byMac: { [MAC]: 'NAS' }, byIp: { [IP]: 'Router' } };
    saveLabels(labels);
    expect(loadLabels()).toEqual(labels);
    // cleanup
    saveLabels({ byMac: {}, byIp: {} });
  });
});

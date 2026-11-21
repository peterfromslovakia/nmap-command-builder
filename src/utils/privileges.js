// ─── Root opravnenia ──────────────────────────────────────────────────────────
//
// Overene s nmap 7.99 na macOS bez rootu. Prikaz sa NEMENI — pouzivatel len
// vidi, ktore flagy root potrebuju a co s nimi nmap bez rootu spravi.
//   quits   — nmap skonci: "requires root privileges. QUITTING!"
//   ignored — sken prebehne, ale volbu nmap ignoruje ("will not be honored")

const ROOT_EFFECTS = {
  ss: { flag: '-sS', effect: 'quits', tip: '-sT (TCP connect) finds the same open ports without root' },
  su: { flag: '-sU', effect: 'quits' },
  sa: { flag: '-sA', effect: 'quits' },
  sn_null: { flag: '-sN', effect: 'quits' },
  sf: { flag: '-sF', effect: 'quits' },
  sx: { flag: '-sX', effect: 'quits' },
  idle_scan: { flag: '-sI', effect: 'quits' },
  os_detect: { flag: '-O', effect: 'quits', tip: '-sV often reports the OS in the "Service Info" line without root' },
  fragment: { flag: '-f', effect: 'quits' },
  mtu: { flag: '--mtu', effect: 'quits' },
  decoy: { flag: '-D', effect: 'quits' },
  spoof_ip: { flag: '-S', effect: 'quits' },
  pu: { flag: '-PU', effect: 'quits', tip: '-PS / -PA ping work without root' },
  traceroute: { flag: '--traceroute', effect: 'quits' },
  spoof_mac: { flag: '--spoof-mac', effect: 'ignored' },
  data_length: { flag: '--data-length', effect: 'ignored' },
  badsum: { flag: '--badsum', effect: 'ignored' },
};

export const ROOT_FLAG_IDS = Object.keys(ROOT_EFFECTS);

const isOn = (v) => !(v === false || v === null || v === undefined || v === '');

/**
 * Ktore z vybranych flagov potrebuju root a co sa bez rootu stane.
 * @returns {Array<{ id, flag, effect: 'quits'|'ignored', tip? }>}
 */
export function rootRequirements(flagSelections) {
  return Object.entries(ROOT_EFFECTS)
    .filter(([id]) => isOn(flagSelections[id]))
    .map(([id, r]) => ({ id, ...r }));
}

/**
 * Prepinace, pre ktore sa sken nesmie spustit s pravami spravcu (ako root by
 * nmap citat/zapisoval subory kdekolvek). Rovnake pravidla kontroluje aj main
 * proces (electron/elevate.js) — toto sluzi len na vysvetlenie v UI.
 */
export function elevationBlockers(args = []) {
  const out = [];
  args.forEach((a, i) => {
    if (['-oN', '-oX', '-oG', '-iL'].includes(a)) out.push(a);
    if (a === '--script' && /[^A-Za-z0-9_,*+() -]/.test(String(args[i + 1] || ''))) out.push('--script <file>');
    if (a === '--script-args' && /[/\\]/.test(String(args[i + 1] || ''))) out.push('--script-args <path>');
  });
  return out;
}

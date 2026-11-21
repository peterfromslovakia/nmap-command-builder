// ─── Beh bez root opravneni ───────────────────────────────────────────────────
//
// Techniky, ktore posielaju vlastne (raw) pakety, potrebuju root. Ak aplikacia
// bezi bez rootu, prikaz sa automaticky upravi:
//   - kde existuje rovnocenna nahrada, flag sa nahradi (napr. -sS → -sT)
//   - kde nahrada neexistuje, flag sa odstrani a pouzivatel dostane vysvetlenie
// Nahlad prikazu vzdy ukazuje presne to, co sa spusti.

// Nahrady: flag → { add: [flagy na zapnutie], remove: [dalsie flagy na vypnutie], note }
const REPLACE = {
  ss: {
    add: ['st'],
    from: '-sS', to: '-sT',
    note: 'TCP connect scan finds the same open ports, it only completes the handshake (more visible in target logs)',
  },
  aggressive: {
    add: ['sv', 'sc'],
    from: '-A', to: '-sV -sC',
    note: 'version detection and default scripts still run; OS detection and traceroute are skipped',
  },
  os_detect: {
    add: ['sv'],
    remove: ['osscan_limit', 'osscan_guess'],
    from: '-O', to: '-sV',
    note: 'OS fingerprinting needs raw packets; -sV often reports the OS in the "Service Info" line',
  },
};

// Bez nahrady — odstrania sa.
const DROP = {
  su: { from: '-sU', note: 'UDP scanning is not possible without root — only TCP ports will be scanned' },
  sa: { from: '-sA', note: 'ACK firewall mapping needs raw packets' },
  sn_null: { from: '-sN', note: 'NULL scan needs raw packets' },
  sf: { from: '-sF', note: 'FIN scan needs raw packets' },
  sx: { from: '-sX', note: 'Xmas scan needs raw packets' },
  idle_scan: { from: '-sI', note: 'idle (zombie) scan needs raw packets' },
  pu: { from: '-PU', note: 'UDP ping needs raw packets' },
  traceroute: { from: '--traceroute', note: 'traceroute needs raw packets' },
  fragment: { from: '-f', note: 'packet fragmentation needs raw packets' },
  mtu: { from: '--mtu', note: 'custom MTU needs raw packets' },
  decoy: { from: '-D', note: 'decoys need raw packets' },
  spoof_ip: { from: '-S', note: 'source IP spoofing needs raw packets' },
  spoof_mac: { from: '--spoof-mac', note: 'MAC spoofing needs raw packets' },
  data_length: { from: '--data-length', note: 'custom packet length needs raw packets' },
  badsum: { from: '--badsum', note: 'bad checksums need raw packets' },
};

const isOn = (v) => !(v === false || v === null || v === undefined || v === '');

/**
 * Upravi vyber flagov pre beh bez rootu.
 * @returns {{ flags: Object, changes: Array<{ from, to, note, kind: 'replaced'|'removed' }> }}
 */
export function adjustForNoRoot(flagSelections) {
  const flags = { ...flagSelections };
  const changes = [];

  for (const [id, rule] of Object.entries(REPLACE)) {
    if (!isOn(flags[id])) continue;
    delete flags[id];
    (rule.remove || []).forEach((r) => delete flags[r]);
    rule.add.forEach((a) => { if (!isOn(flags[a])) flags[a] = true; });
    changes.push({ kind: 'replaced', from: rule.from, to: rule.to, note: rule.note });
  }

  for (const [id, rule] of Object.entries(DROP)) {
    if (!isOn(flags[id])) continue;
    delete flags[id];
    changes.push({ kind: 'removed', from: rule.from, to: '', note: rule.note });
  }

  return { flags, changes };
}

/** Jednoriadkovy popis zmien (pre tooltip a terminal). */
export function describeChanges(changes) {
  return changes
    .map((c) => (c.kind === 'replaced' ? `${c.from} → ${c.to}: ${c.note}` : `${c.from} removed: ${c.note}`))
    .join('\n');
}

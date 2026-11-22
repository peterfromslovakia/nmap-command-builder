/**
 * Klasifikácia skenu podľa príkazu — aby sme vedeli, čo sken testoval
 * a mohli správne porovnávať výsledky a hodnotiť riziko.
 */

/**
 * Typy skenu (od najobmedzenejšieho po najúplnejší):
 *   discovery  — len ping / host-alive check (-sn / -sP); porty sa netestujú
 *   port       — porty sa testujú, ale bez detekcie verzií a bez NSE skriptov
 *   service    — detekcia verzií (-sV / -A bez vuln skriptov)
 *   vuln       — vulnerability skripty (vuln, vulners, exploit, …)
 */
export function detectScanType(command) {
  const args = String(command || '').split(/\s+/).filter(Boolean).slice(1);
  const has = (f) => args.includes(f);
  const val = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : ''; };

  // Ping-only: len živosť hostov, žiadne porty
  if (has('-sn') || has('-sP')) return 'discovery';

  // Vuln skripty
  const scripts = val('--script');
  if (scripts) {
    const sc = scripts.toLowerCase();
    if (/\b(vuln|vulners|exploit|malware|intrusive)\b/.test(sc)) return 'vuln';
  }
  if (has('-sC') || has('-A')) {
    // -A spúšťa default skripty (žiadne vuln), ale má verzie + OS
    return 'service';
  }

  if (has('-sV')) return 'service';

  return 'port';
}

/**
 * Vráti true, ak sken vôbec netestoval porty.
 * Na to, aby sme neoznačili netestované porty ako "zatvorené".
 */
export function isDiscoveryScan(command) {
  return detectScanType(command) === 'discovery';
}

/**
 * Vráti true, ak sken spúšťal vulnerability skripty.
 * Na to, aby sme rozlíšili "žiadne nálezy" od "netestované".
 */
export function isVulnScan(command) {
  return detectScanType(command) === 'vuln';
}

/**
 * Porovná, či majú dve skeny porovnateľnú metodiku pre porty.
 * Ak nie, diff by nemal označovať porty ako zatvorené.
 */
export function arePortsComparable(cmd1, cmd2) {
  const t1 = detectScanType(cmd1);
  const t2 = detectScanType(cmd2);
  // Discovery sken netestuje porty — nič z neho nemôže byť "zatvorené"
  if (t1 === 'discovery' || t2 === 'discovery') return false;
  return true;
}

/**
 * Porovná, či majú dve skeny porovnateľnú metodiku pre nálezy/zraniteľnosti.
 * Ak nie, diff by nemal označovať nálezy ako "opravené".
 *
 * Pravidlá:
 * - Discovery sken (-sn) netestuje nič → vždy neporovnateľné
 * - Ak jeden sken spúšťal vuln skripty a druhý nie → neporovnateľné
 *   (mohli by sme tvrdiť "opravené" len preto, že neboli testované)
 * - Rovnaká úroveň (oba port/service alebo oba vuln) → porovnateľné
 */
/**
 * Vráti normalizovanú špecifikáciu portov z príkazu.
 * Používa sa na detekciu, keď dve skenovania testovali rôzne porty
 * a diff by mohol falošne hlásiť "zatvorené" porty.
 *
 * Vracia:
 *   'all'        — -p- (všetky porty)
 *   'fast'       — -F (100 portov)
 *   'topN'       — --top-ports N
 *   '<spec>'     — explicitný -p argument (napr. "80,443" alebo "1-1000")
 *   'default'    — žiaden port argument (nmap default: top 1000)
 */
export function getPortSpec(command) {
  const args = String(command || '').split(/\s+/).filter(Boolean).slice(1);
  if (args.includes('-p-')) return 'all';
  if (args.includes('-F')) return 'fast';
  const pIdx = args.indexOf('-p');
  if (pIdx >= 0 && args[pIdx + 1] && !args[pIdx + 1].startsWith('-')) return args[pIdx + 1];
  const topIdx = args.indexOf('--top-ports');
  if (topIdx >= 0 && args[topIdx + 1]) return `top${args[topIdx + 1]}`;
  return 'default';
}

/**
 * Vráti true ak príkaz spúšťal vulnerability skripty (NSE vuln/vulners/vulscan/exploit).
 * Ak nie, "žiadne nálezy" neznamená "bezpečné systémy" — testovanie zraniteľností neprebehlo.
 */
export function hasVulnScripts(command) {
  const a = String(command || '').split(/\s+/).filter(Boolean).slice(1);
  const has = (f) => a.includes(f);
  if (has('-sC') || has('-A')) return true; // default scripts zahŕňajú bezpečnostné kontroly
  if (has('--script')) {
    const val = a[a.indexOf('--script') + 1] || '';
    return /vuln|exploit|vulscan|vulners|malware|backdoor|auth|brute|safe/i.test(val);
  }
  return false;
}

/**
 * Vráti true ak príkaz obsahuje --open (zobrazujú sa len open porty).
 * V tom prípade neprítomný port nemusí byť closed — môže byť filtered alebo closed.
 * Nesmieme ho klasifikovať ako "closed" bez ďalšieho dôkazu.
 */
/**
 * Vráti true ak sken spúšťal detekciu verzií/služieb (-sV alebo -A).
 * Bez toho sú názvy služieb len odhadom podľa čísla portu (IANA registry).
 */
export function hasServiceDetection(command) {
  const a = String(command || '').split(/\s+/).filter(Boolean).slice(1);
  return a.includes('-sV') || a.includes('-A');
}

export function hasOpenOnly(command) {
  return String(command || '').split(/\s+/).includes('--open');
}

export function areVulnsComparable(cmd1, cmd2) {
  const t1 = detectScanType(cmd1);
  const t2 = detectScanType(cmd2);
  if (t1 === 'discovery' || t2 === 'discovery') return false;
  // Ak jeden má vuln skripty a druhý nie — zmiznuté nálezy sú zavádzajúce
  const oneHasVuln = t1 === 'vuln' || t2 === 'vuln';
  if (oneHasVuln && t1 !== t2) return false;
  // Ak jeden sken spúšťal NSE skripty (-sC/-A) a druhý nie (-sV), nálezy pochádzajú
  // z rôznych zdrojov — zmiznutý nález mohol byť jednoducho netestovaný, nie opravený.
  if (hasVulnScripts(cmd1) !== hasVulnScripts(cmd2)) return false;
  return true;
}

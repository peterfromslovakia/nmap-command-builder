import { FLAG_MAP } from '../data/flags';
import { sanitizeArg } from './validator';

/**
 * Build the nmap args array from user selections.
 *
 * @param {string}  target          - raw target string
 * @param {Object}  flagSelections  - { flagId: true|string|number }
 * @param {boolean} advancedMode    - show/use advanced flags
 * @returns {{ args, command, warnings, requiresRoot, hasTarget }}
 */
export function buildCommand(target, flagSelections, advancedMode) {
  const args = [];
  const warnSet = new Set();
  let requiresRoot = false;

  for (const [flagId, value] of Object.entries(flagSelections)) {
    // Skip falsy values
    if (value === false || value === null || value === undefined || value === '') continue;

    const def = FLAG_MAP[flagId];
    if (!def) continue;

    // In safe mode skip advanced flags
    if (!def.safe && !advancedMode) continue;

    if (def.requiresRoot) requiresRoot = true;
    if (def.warning) warnSet.add(def.warning);

    switch (def.type) {
      case 'boolean':
        // value must be === true
        if (value === true) args.push(def.flag);
        break;

      case 'select':
        // -T4 is always concatenated (no space)
        if (value) args.push(`${def.flag}${value}`);
        break;

      case 'text':
      case 'number': {
        const clean = sanitizeArg(String(value));
        if (clean) {
          // -PS/-PA/-PU port lists are appended without space in nmap convention
          if (def.flag === '-PS' || def.flag === '-PA' || def.flag === '-PU') {
            args.push(`${def.flag}${clean}`);
          } else {
            args.push(def.flag, clean);
          }
        }
        break;
      }

      default:
        break;
    }
  }

  const safeTarget = sanitizeArg(target || '');
  if (safeTarget) args.push(safeTarget);

  const command = `nmap ${args.join(' ')}`.trimEnd();

  return {
    args,
    command: args.length === 0 ? 'nmap' : command,
    warnings: Array.from(warnSet),
    requiresRoot,
    hasTarget: Boolean(safeTarget),
  };
}

/**
 * Parse nmap output lines to extract a simple summary.
 * Returns { hosts, openPorts, services }
 */
export function parseScanSummary(lines) {
  let hosts = 0;
  const openPorts = [];
  const services = new Set();

  for (const line of lines) {
    // Split each chunk into individual sub-lines so that the ^ anchor in the
    // port regex works correctly even when a single stdout 'data' event
    // contains multiple newline-separated lines.
    const sublines = (line.text || '').split('\n');

    for (const t of sublines) {
      // Count "Nmap scan report for" occurrences
      if (/Nmap scan report for/i.test(t)) hosts++;

      // Match open port lines: "80/tcp   open  http   Apache httpd"
      const m = t.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?/i);
      if (m) {
        openPorts.push({ port: m[1], proto: m[2], service: m[3], version: (m[4] || '').trim() });
        services.add(m[3]);
      }
    }
  }

  return { hosts, openPorts, services: Array.from(services) };
}

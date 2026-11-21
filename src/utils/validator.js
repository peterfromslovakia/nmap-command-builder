// ─── Target Validation ────────────────────────────────────────────────────────
//
// Poznamka: nmap sa spusta cez spawn() bez shellu, takze shell metaznaky nie su
// primarne riziko. Zoznam nizsie je len obranna vrstva. Lomka "/" v nom NIE JE,
// pretoze je platnou castou CIDR targetov (192.168.1.0/24) aj ciest k suborom.

// eslint-disable-next-line no-control-regex -- riadiace znaky su zamerne zakazane
const UNSAFE_CHARS = /[;&|`$(){}[\]<>!\\'"\u0000-\u001f\u007f]/;

const RE_IPV4_LOOSE = /^(\d{1,3}\.){3}\d{1,3}$/;
const RE_CIDR       = /^((?:\d{1,3}\.){3}\d{1,3})\/(\d{1,2})$/;
const RE_IP_RANGE   = /^((?:\d{1,3}\.){3})(\d{1,3})-(\d{1,3})$/;
const RE_HOSTNAME   = /^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$/;
const RE_WILDCARD   = /^(\d{1,3}|\*)(\.(\d{1,3}|\*))*$/;

function octetsOk(ip) {
  return ip.split('.').every((o) => Number(o) >= 0 && Number(o) <= 255);
}

function isValidPart(part) {
  const p = part.trim();
  if (!p || p.length > 253) return false;

  if (RE_IPV4_LOOSE.test(p)) return octetsOk(p);

  let m = p.match(RE_CIDR);
  if (m) return octetsOk(m[1]) && Number(m[2]) >= 0 && Number(m[2]) <= 32;

  m = p.match(RE_IP_RANGE);
  if (m) {
    const [, prefix, from, to] = m;
    return octetsOk(`${prefix}${from}`) && Number(to) <= 255 && Number(from) <= Number(to);
  }

  return RE_HOSTNAME.test(p) || RE_WILDCARD.test(p);
}

export function validateTarget(target) {
  const t = (target || '').trim();
  if (!t) return { valid: false, error: 'Target is required' };
  if (UNSAFE_CHARS.test(t)) return { valid: false, error: 'Target contains invalid characters' };
  for (const part of t.split(',')) {
    if (!isValidPart(part)) {
      return { valid: false, error: `Invalid target: "${part.trim()}"` };
    }
  }
  return { valid: true };
}

// ─── Flag Value Validation ────────────────────────────────────────────────────

export function validateFlagValue(flagDef, value) {
  if (flagDef.type === 'boolean') return { valid: true };
  if (value === '' || value === null || value === undefined) {
    return { valid: false, error: `${flagDef.name} requires a value` };
  }
  const str = String(value).trim();
  if (UNSAFE_CHARS.test(str)) {
    return { valid: false, error: 'Value contains invalid characters' };
  }
  // Hodnota zacinajuca "-" by sa v nmape interpretovala ako dalsi prepinac.
  if (str.startsWith('-') && flagDef.flag !== '-PS' && flagDef.flag !== '-PA' && flagDef.flag !== '-PU') {
    return { valid: false, error: `${flagDef.name}: value must not start with "-"` };
  }
  if (flagDef.type === 'number') {
    const n = parseFloat(str);
    if (isNaN(n)) return { valid: false, error: `${flagDef.name}: must be a number` };
    if (flagDef.min !== undefined && n < flagDef.min)
      return { valid: false, error: `${flagDef.name}: min ${flagDef.min}` };
    if (flagDef.max !== undefined && n > flagDef.max)
      return { valid: false, error: `${flagDef.name}: max ${flagDef.max}` };
  }
  return { valid: true };
}

// ─── Arg Sanitizer ────────────────────────────────────────────────────────────

// Odstrani nebezpecne znaky z jedneho argumentu. Lomka sa zachovava (CIDR, cesty).
export function sanitizeArg(value) {
  return String(value).replace(new RegExp(UNSAFE_CHARS.source, 'g'), '').trim();
}

// ─── Target Validation ────────────────────────────────────────────────────────

const SHELL_METACHAR = /[;&|`$(){}[\]<>!\\'"/]/;

// Accept: single IP, CIDR, IP range, hostname, wildcard IP, comma-separated list
const RE_IPV4      = /^(\d{1,3}\.){3}\d{1,3}$/;
const RE_CIDR      = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
const RE_IP_RANGE  = /^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$/;
const RE_HOSTNAME  = /^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$/;
const RE_WILDCARD  = /^(\d{1,3}|\*)(\.(\d{1,3}|\*))*$/;

function isValidPart(part) {
  const p = part.trim();
  if (!p) return false;
  return (
    RE_IPV4.test(p) ||
    RE_CIDR.test(p) ||
    RE_IP_RANGE.test(p) ||
    RE_HOSTNAME.test(p) ||
    RE_WILDCARD.test(p)
  );
}

export function validateTarget(target) {
  const t = (target || '').trim();
  if (!t) return { valid: false, error: 'Target is required' };
  if (SHELL_METACHAR.test(t)) return { valid: false, error: 'Target contains invalid characters' };
  const parts = t.split(',');
  for (const part of parts) {
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
  if (SHELL_METACHAR.test(str)) {
    return { valid: false, error: 'Value contains invalid characters' };
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

// Strip dangerous shell characters from a single argument string.
// Used as a final safety layer before passing args to spawn.
export function sanitizeArg(value) {
  return String(value).replace(/[;&|`$(){}[\]<>!\\'"/]/g, '').trim();
}

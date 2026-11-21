// Pomocne funkcie pre hodnoty --script a --script-args (comma-separated).
// Polozky s medzerou (napr. "default and safe") sa zachovavaju ako celok.

export function parseList(value) {
  return String(value || '')
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);
}

/** Prida skript/kategoriu, alebo ju odoberie ak uz je vybrana. */
export function toggleScript(value, name) {
  const list = parseList(value);
  const next = list.includes(name) ? list.filter((x) => x !== name) : [...list, name];
  return next.join(',');
}

/** Odstrani zo zoznamu dane polozky (napr. pri prepnuti z ADV do SAFE). */
export function removeScripts(value, names) {
  const drop = new Set(names);
  return parseList(value).filter((x) => !drop.has(x)).join(',');
}

/** Prida key=value do --script-args, ak tam dany kluc este nie je. */
export function addScriptArg(value, key, example) {
  const list = parseList(value);
  if (list.some((x) => x.split('=')[0].trim() === key)) return list.join(',');
  return [...list, `${key}=${example}`].join(',');
}

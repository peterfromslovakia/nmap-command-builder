// ─── Zapamatanie velkosti a polohy okna ───────────────────────────────────────
// Ulozene v userData/window-state.json. Pri obnoveni sa overi, ze okno je
// viditelne na niektorom z aktualnych monitorov (napr. po odpojeni externeho
// monitora by sa inak otvorilo mimo obrazovky).

const fs = require('fs');

const num = (v) => (Number.isFinite(v) ? Math.round(v) : null);

function readState(file) {
  try {
    const s = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!s || typeof s !== 'object') return null;
    return {
      x: num(s.x), y: num(s.y), width: num(s.width), height: num(s.height),
      maximized: s.maximized === true,
    };
  } catch (_) {
    return null;
  }
}

function overlap(a, b) {
  const w = Math.min(a.x + a.width, b.x + b.width) - Math.max(a.x, b.x);
  const h = Math.min(a.y + a.height, b.y + b.height) - Math.max(a.y, b.y);
  return w > 0 && h > 0 ? w * h : 0;
}

/**
 * Vypocita bounds okna z ulozeneho stavu.
 * @param {object|null} state    ulozeny stav (readState)
 * @param {Array<{x,y,width,height}>} workAreas  pracovne plochy monitorov (prvy = hlavny)
 * @param {{width,height,minWidth,minHeight}} def predvolene rozmery
 */
function resolveBounds(state, workAreas, def) {
  const primary = workAreas[0] || { x: 0, y: 0, width: def.width, height: def.height };
  const fit = (area, w, h) => ({
    width: Math.max(Math.min(w, area.width), Math.min(def.minWidth, area.width)),
    height: Math.max(Math.min(h, area.height), Math.min(def.minHeight, area.height)),
  });

  if (state && state.width && state.height && state.x !== null && state.y !== null) {
    const rect = { x: state.x, y: state.y, width: state.width, height: state.height };
    // Monitor, na ktorom je najvacsia cast okna; aspon 100×100 px musi byt viditelnych.
    const best = workAreas
      .map((a) => ({ a, o: overlap(rect, a) }))
      .sort((p, q) => q.o - p.o)[0];
    if (best && best.o >= 100 * 100) {
      const area = best.a;
      const size = fit(area, state.width, state.height);
      const x = Math.min(Math.max(state.x, area.x), area.x + area.width - size.width);
      const y = Math.min(Math.max(state.y, area.y), area.y + area.height - size.height);
      return { ...size, x, y, maximized: Boolean(state.maximized) };
    }
  }

  // Bez ulozeneho stavu (alebo mimo obrazovky): predvolena velkost, vycentrovane.
  const size = fit(primary, def.width, def.height);
  return {
    ...size,
    x: primary.x + Math.round((primary.width - size.width) / 2),
    y: primary.y + Math.round((primary.height - size.height) / 2),
    maximized: Boolean(state && state.maximized),
  };
}

function writeState(file, win) {
  try {
    const b = win.getNormalBounds();
    fs.writeFileSync(file, JSON.stringify({ ...b, maximized: win.isMaximized() }));
  } catch (_) { /* nepodstatne — nabuduce sa pouziju predvolene rozmery */ }
}

module.exports = { readState, resolveBounds, writeState };

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { readState, resolveBounds, writeState } = require('./windowState');

const DEF = { width: 1440, height: 920, minWidth: 1100, minHeight: 700 };
const LAPTOP = { x: 0, y: 25, width: 1512, height: 920 };
const EXTERNAL = { x: 1512, y: 0, width: 2560, height: 1415 };

test('no saved state: default size centered on the primary display', () => {
  assert.deepStrictEqual(resolveBounds(null, [EXTERNAL], DEF),
    { width: 1440, height: 920, x: 1512 + 560, y: 248, maximized: false });
});

test('restores position on an external monitor', () => {
  const s = { x: 1700, y: 100, width: 1800, height: 1100, maximized: false };
  assert.deepStrictEqual(resolveBounds(s, [LAPTOP, EXTERNAL], DEF), { ...s });
});

test('window left on a disconnected monitor comes back to the primary one', () => {
  const s = { x: 1700, y: 100, width: 1800, height: 1100, maximized: true };
  const r = resolveBounds(s, [LAPTOP], DEF);
  assert.strictEqual(r.maximized, true);
  assert.ok(r.x >= LAPTOP.x && r.x + r.width <= LAPTOP.x + LAPTOP.width);
  assert.ok(r.y >= LAPTOP.y && r.y + r.height <= LAPTOP.y + LAPTOP.height);
});

test('oversized or partly off-screen window is shrunk and moved inside', () => {
  const r = resolveBounds({ x: -300, y: 500, width: 4000, height: 3000 }, [LAPTOP], DEF);
  assert.deepStrictEqual(r, { x: 0, y: 25, width: 1512, height: 920, maximized: false });
});

test('small screen: never larger than the work area, even below minimum', () => {
  const tiny = { x: 0, y: 0, width: 1024, height: 640 };
  const r = resolveBounds(null, [tiny], DEF);
  assert.strictEqual(r.width, 1024);
  assert.strictEqual(r.height, 640);
});

test('read/write roundtrip; broken or missing file is ignored', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ncb-ws-'));
  const file = path.join(dir, 'window-state.json');
  assert.strictEqual(readState(file), null);
  writeState(file, { getNormalBounds: () => ({ x: 10, y: 20, width: 1300, height: 800 }), isMaximized: () => true });
  assert.deepStrictEqual(readState(file), { x: 10, y: 20, width: 1300, height: 800, maximized: true });
  fs.writeFileSync(file, '{oops');
  assert.strictEqual(readState(file), null);
  fs.writeFileSync(file, JSON.stringify({ x: 'a', width: 1e400 }));
  assert.deepStrictEqual(readState(file), { x: null, y: null, width: null, height: null, maximized: false });
  fs.rmSync(dir, { recursive: true });
});

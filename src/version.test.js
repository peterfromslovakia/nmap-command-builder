// Verzia v patičke aplikacie musi sediet s package.json (kontrola pri vydani).
const fs = require('fs');
const path = require('path');

test('footer version matches package.json', () => {
  const { version } = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  const app = fs.readFileSync(path.join(__dirname, 'App.js'), 'utf8');
  expect(app).toContain(`Nmap Command Builder v${version}<`);
});

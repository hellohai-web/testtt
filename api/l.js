'use strict';
// Layer 3: the video engine is only handed out to a visitor who passed layer 1 + 2 on this device.
const fs = require('fs');
const path = require('path');
const h = require('./_h.js');

let cache = null;
const SOURCES = [
  'https://cdn.jsdelivr.net/npm/mediabunny@1.61.3/+esm',
  'https://cdn.jsdelivr.net/npm/mediabunny@1.61.3/dist/bundles/mediabunny.min.mjs',
  'https://cdn.jsdelivr.net/npm/mediabunny@1.61.3/dist/bundles/mediabunny.mjs',
];
// Only the label/comments that spell out the library name are removed. The code itself is not touched.
function tidy(code) {
  code = code.replace(/^\s*\/\*\*?[\s\S]*?\*\/\s*/, (m) => (/jsdelivr|bundled|original file|mediabunny/i.test(m) ? '' : m));
  return code.replace(/\n?\/\/# sourceMappingURL=.*\s*$/, '\n');
}
const looksOk = (c) => typeof c === 'string' && c.length > 20000 && /\bexport\b/.test(c);

async function getLib() {
  if (cache) return cache;
  try { // optional: a copy bundled with the site (tools/build.mjs --lib file) so no outside server is needed
    const c = fs.readFileSync(path.join(__dirname, '_m.dat'), 'utf8');
    if (looksOk(c)) return (cache = tidy(c));
  } catch {}
  for (const u of SOURCES) {
    try {
      const ac = new AbortController();
      const to = setTimeout(() => ac.abort(), 12000);
      const r = await fetch(u, { signal: ac.signal });
      clearTimeout(to);
      if (!r.ok) continue;
      const c = await r.text();
      if (looksOk(c)) return (cache = tidy(c));
    } catch {}
  }
  return null;
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const sec = h.secret();
    if (!sec || (req.method !== 'GET' && req.method !== 'HEAD')) { res.statusCode = 401; return res.end(); }
    const s = await h.checkSession(req, sec);
    if (!s.ok) { res.statusCode = 401; return res.end(); }
    res.setHeader('Content-Type', 'text/javascript; charset=utf-8');
    if (req.method === 'HEAD') { res.statusCode = 200; return res.end(); }
    const code = await getLib();
    if (!code) { res.statusCode = 502; return res.end(); }
    res.statusCode = 200;
    return res.end(code);
  } catch (e) {
    res.statusCode = 500; return res.end();
  }
};

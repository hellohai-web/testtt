'use strict';
// Shared helpers for the API (not a public route because the file name starts with "_").
const crypto = require('crypto');

const HM = (s, m) => crypto.createHmac('sha256', s).update(m).digest();
const b64u = (x) => Buffer.from(x).toString('base64url');
const safeEq = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const now = () => Math.floor(Date.now() / 1000);

function secret() {
  const s = process.env.APP_SECRET;
  return s && s.length >= 32 ? s : null;
}

// ---- signed tokens (stage token + session) ----
function sign(payload, sec) {
  const p = b64u(JSON.stringify(payload));
  return p + '.' + b64u(HM(sec, 'tok:' + p));
}
function verify(tok, sec) {
  if (typeof tok !== 'string' || tok.length > 600) return null;
  const [p, t] = tok.split('.');
  if (!p || !t || !safeEq(t, b64u(HM(sec, 'tok:' + p)))) return null;
  try {
    const o = JSON.parse(Buffer.from(p, 'base64url').toString());
    return o && o.e > now() ? o : null;
  } catch { return null; }
}

// ---- license keys: status-0001-AAAA-BBBB-CCCC-DDDD (signed, so no list is needed) ----
const keyTag = (serial, sec) => HM(sec, 'status-key-v1:' + serial).toString('hex').slice(0, 16).toUpperCase();
function checkKey(input, sec) {
  if (typeof input !== 'string' || input.length > 80) return null;
  const c = input.toUpperCase().replace(/[^A-Z0-9]/g, '');
  const m = /^STATUS(\d{4,6})([0-9A-F]{16})$/.exec(c);
  if (!m) return null;
  return safeEq(m[2], keyTag(m[1], sec)) ? m[1] : null;
}
const pageKey = (sec) => HM(sec, 'page-key-v1');           // 32 bytes, opens the encrypted page
const adminToken = (sec) => HM(sec, 'admin-v1').toString('hex');

// ---- cookies ----
function cookies(req) {
  const o = {};
  String(req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) o[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return o;
}
function setCookies(res, list) {
  res.setHeader('Set-Cookie', list.map(([n, v, age]) =>
    `${n}=${v}; Path=/; Max-Age=${age}; HttpOnly; Secure; SameSite=Lax`));
}
const DID_RE = /^[0-9a-f]{32}$/;
const devHash = (did) => crypto.createHash('sha256').update('dev:' + did).digest('hex').slice(0, 32);

// ---- database (Upstash Redis over REST; works with the Vercel Marketplace integration) ----
const mem = new Map(); // only used when TEST_MEMORY_STORE=1 (local tests)
function dbConfig() {
  if (process.env.TEST_MEMORY_STORE === '1') return { test: true };
  const url = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
  return url && token ? { url: url.replace(/\/+$/, ''), token } : null;
}
function memRun(cmd) {
  const [op, k, a, ...rest] = cmd;
  const t = Date.now();
  const e = mem.get(k);
  if (e && e.x && e.x < t) mem.delete(k);
  const cur = mem.get(k);
  switch (String(op).toUpperCase()) {
    case 'PING': return 'PONG';
    case 'GET': return cur ? cur.v : null;
    case 'DEL': { const had = mem.delete(k); return had ? 1 : 0; }
    case 'SET': {
      if (rest.map(String).includes('NX') && cur) return null;
      mem.set(k, { v: String(a) }); return 'OK';
    }
    case 'INCR': { const n = (cur ? Number(cur.v) : 0) + 1; mem.set(k, { v: String(n), x: cur && cur.x }); return n; }
    case 'EXPIRE': { if (cur) cur.x = t + Number(a) * 1000; return cur ? 1 : 0; }
    default: throw new Error('mem cmd');
  }
}
async function db(cmds) {
  const c = dbConfig();
  if (!c) throw new Error('NO_DB');
  if (c.test) return cmds.map(memRun);
  const ac = new AbortController();
  const to = setTimeout(() => ac.abort(), 8000);
  try {
    const r = await fetch(c.url + '/pipeline', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + c.token, 'Content-Type': 'application/json' },
      body: JSON.stringify(cmds),
      signal: ac.signal,
    });
    if (!r.ok) throw new Error('DB_HTTP_' + r.status);
    const j = await r.json();
    return j.map((x) => { if (x.error) throw new Error('DB_ERR'); return x.result; });
  } finally { clearTimeout(to); }
}

// ---- small helpers ----
function ip(req) {
  const f = req.headers['x-vercel-forwarded-for'] || req.headers['x-forwarded-for'] || (req.socket && req.socket.remoteAddress) || '';
  return String(f).split(',')[0].trim();
}
async function rateLimit(req, bucket, limit, windowSec) {
  try {
    const k = `rl:${bucket}:${crypto.createHash('sha256').update(ip(req)).digest('hex').slice(0, 16)}`;
    const r = await db([['INCR', k], ['EXPIRE', k, windowSec]]);
    return Number(r[0]) <= limit;
  } catch { return true; } // if the database is down, the stage itself will report the problem
}
function sameOrigin(req) {
  const o = req.headers.origin;
  if (!o) return true;
  try { return new URL(o).host === req.headers.host; } catch { return false; }
}
function send(res, code, obj) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(obj));
}

// ---- session check (used by the page and by the library endpoint) ----
// Valid only if: signed session cookie + the key is still bound to THIS device + key not revoked.
async function checkSession(req, sec, didFromBody) {
  const ck = cookies(req);
  const s = verify(ck.ses, sec);
  if (!s) return { ok: false, err: 'none' };
  const did = DID_RE.test(ck.did || '') ? ck.did : (DID_RE.test(didFromBody || '') ? didFromBody : '');
  if (!did || devHash(did) !== s.d) return { ok: false, err: 'none' };
  let r;
  try { r = await db([['GET', 'dev:' + s.k], ['GET', 'rev:' + s.k]]); } catch { return { ok: false, err: 'db' }; }
  if (r[1]) return { ok: false, err: 'revoked' };
  if (r[0] !== s.d) return { ok: false, err: 'none' };
  return { ok: true, serial: s.k, did, dh: s.d };
}

module.exports = {
  crypto, HM, b64u, safeEq, now, secret, sign, verify, checkKey, keyTag, pageKey, adminToken,
  cookies, setCookies, DID_RE, devHash, db, dbConfig, ip, rateLimit, sameOrigin, send, checkSession,
};

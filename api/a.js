'use strict';
const h = require('./_h.js');
const cfg = require('./_cfg.js');

function envPw() {
  const p = String(process.env.SITE_PASSWORD || '').trim().toLowerCase();
  return p.length >= 8 ? p : null;
}
// SITE_PASSWORD (set in Vercel) wins. If it is not set, the password built by tools/build.mjs is used.
function pwOk(pw) {
  if (typeof pw !== 'string' || pw.length > 100) return false;
  const norm = pw.trim().toLowerCase();
  const e = envPw();
  if (e) {
    const sh = (x) => h.crypto.createHash('sha256').update(x).digest();
    return h.crypto.timingSafeEqual(sh(norm), sh(e));
  }
  const got = h.crypto.scryptSync(norm, Buffer.from(cfg.salt, 'hex'), 32).toString('hex');
  return h.safeEq(got, cfg.hash);
}
const body = (req) => {
  let b = req.body;
  if (typeof b === 'string') { try { b = JSON.parse(b); } catch { b = null; } }
  return b && typeof b === 'object' ? b : {};
};
const DAY = 86400;

module.exports = async (req, res) => {
  try {
    const sec = h.secret();

    // Open /api/a in the browser to see if everything is set up correctly.
    if (req.method === 'GET') {
      const out = { ok: !!sec, secret: !!sec, database: !!h.dbConfig(), site_password: envPw() ? 'set in Vercel' : 'NOT set (using built-in one)' };
      if (sec && out.database) {
        try { await h.db([['PING']]); out.databaseReachable = true; } catch (e) { out.databaseReachable = false; }
      }
      out.ready = !!(out.secret && out.database && out.databaseReachable);
      return h.send(res, 200, out);
    }
    if (req.method !== 'POST') return h.send(res, 405, { ok: false, err: 'method' });
    if (!h.sameOrigin(req)) return h.send(res, 403, { ok: false, err: 'origin' });
    if (!sec) return h.send(res, 200, { ok: false, err: 'cfg', detail: 'APP_SECRET is missing or too short (needs 32+ characters).' });

    const b = body(req);
    const t = h.now();

    // ---------- Layer 1: password (only checked here on the server) ----------
    if (b.a === 'pw') {
      if (!(await h.rateLimit(req, 'pw', 10, 600))) return h.send(res, 429, { ok: false, err: 'many' });
      if (!pwOk(b.pw)) return h.send(res, 200, { ok: false, err: 'pw' });
      return h.send(res, 200, { ok: true, t1: h.sign({ s: 1, e: t + 900 }, sec) });
    }

    // ---------- Layer 2: key, one key = one device ----------
    if (b.a === 'key') {
      if (!h.dbConfig()) return h.send(res, 200, { ok: false, err: 'cfg', detail: 'Database is not connected yet (Vercel Storage > Upstash Redis).' });
      if (!(await h.rateLimit(req, 'key', 12, 600))) return h.send(res, 429, { ok: false, err: 'many' });
      const st = h.verify(b.t1, sec);
      if (!st || st.s !== 1) return h.send(res, 200, { ok: false, err: 'expired' });
      const serial = h.checkKey(b.key, sec);
      if (!serial) return h.send(res, 200, { ok: false, err: 'key' });

      const ck = h.cookies(req);
      const did = h.DID_RE.test(ck.did || '') ? ck.did
        : (h.DID_RE.test(b.did || '') ? b.did : h.crypto.randomBytes(16).toString('hex'));
      const dh = h.devHash(did);

      let r;
      try {
        r = await h.db([['GET', 'rev:' + serial], ['SET', 'dev:' + serial, dh, 'NX'], ['GET', 'dev:' + serial]]);
      } catch (e) { return h.send(res, 200, { ok: false, err: 'cfg', detail: 'Database error (' + String(e.message).slice(0, 40) + ').' }); }
      if (r[0]) return h.send(res, 200, { ok: false, err: 'revoked' });
      if (r[2] !== dh) return h.send(res, 200, { ok: false, err: 'used' });
      if (r[1] === 'OK') {
        try {
          await h.db([['SET', 'inf:' + serial, JSON.stringify({ at: new Date().toISOString(), ua: String(req.headers['user-agent'] || '').slice(0, 140) })]]);
        } catch {}
      }
      const ses = h.sign({ k: serial, d: dh, e: t + 30 * DAY }, sec);
      h.setCookies(res, [['did', did, 400 * DAY], ['ses', ses, 30 * DAY]]);
      return h.send(res, 200, { ok: true, pk: h.pageKey(sec).toString('base64'), did });
    }

    // ---------- Returning visitor: session still valid on this device? ----------
    if (b.a === 'ses') {
      if (!h.dbConfig()) return h.send(res, 200, { ok: false, err: 'cfg', detail: 'Database is not connected yet (Vercel Storage > Upstash Redis).' });
      const s = await h.checkSession(req, sec, b.did);
      if (!s.ok) return h.send(res, 200, { ok: false, err: s.err });
      const ses = h.sign({ k: s.serial, d: s.dh, e: t + 30 * DAY }, sec);
      h.setCookies(res, [['did', s.did, 400 * DAY], ['ses', ses, 30 * DAY]]);
      return h.send(res, 200, { ok: true, pk: h.pageKey(sec).toString('base64'), did: s.did });
    }

    // ---------- Owner tools (tools/keys.mjs) ----------
    if (b.a === 'adm') {
      if (!(await h.rateLimit(req, 'adm', 30, 600))) return h.send(res, 429, { ok: false, err: 'many' });
      if (!h.safeEq(req.headers['x-admin'] || '', h.adminToken(sec))) return h.send(res, 403, { ok: false, err: 'admin' });
      const n = String(b.n || '').replace(/\D/g, '').padStart(4, '0');
      if (!/^\d{4,6}$/.test(n)) return h.send(res, 200, { ok: false, err: 'serial' });
      if (b.op === 'reset') await h.db([['DEL', 'dev:' + n], ['DEL', 'inf:' + n]]);
      else if (b.op === 'revoke') await h.db([['SET', 'rev:' + n, '1']]);
      else if (b.op === 'unrevoke') await h.db([['DEL', 'rev:' + n]]);
      else if (b.op !== 'status') return h.send(res, 200, { ok: false, err: 'op' });
      const r = await h.db([['GET', 'dev:' + n], ['GET', 'rev:' + n], ['GET', 'inf:' + n]]);
      let info = null; try { info = r[2] ? JSON.parse(r[2]) : null; } catch {}
      return h.send(res, 200, { ok: true, serial: n, used: !!r[0], revoked: !!r[1], first_used: info && info.at, device: info && info.ua });
    }

    return h.send(res, 400, { ok: false, err: 'bad' });
  } catch (e) {
    return h.send(res, 500, { ok: false, err: 'server' });
  }
};

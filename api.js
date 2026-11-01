'use strict';
/*
 * Cozmo online accounts and shared content (HTTP API). No dependencies.
 *
 * Data lives in a Firebase Realtime Database (free), reached over its REST interface with a
 * service account key. If no key is set the data is kept in memory only (good for testing).
 *
 * Settings (environment variables):
 *   FIREBASE_URL   the database address, e.g. https://xxxx-default-rtdb.europe-west1.firebasedatabase.app
 *   FIREBASE_KEY   the service account JSON (paste the whole file, or its base64)
 *                  or put the file in Render "Secret Files" as firebase.json
 *   ADMIN_NAME     the account that is the admin (default Vahxx)
 *   TOKEN_SECRET   optional, any long random text used to sign login tokens
 */
const crypto = require('crypto');
const https = require('https');
const http = require('http');
const fs = require('fs');

const ADMIN_KEY = String(process.env.ADMIN_NAME || 'Vahxx').toLowerCase();
const FB_URL = String(process.env.FIREBASE_URL || 'https://cozmo-3e590-default-rtdb.europe-west1.firebasedatabase.app').replace(/\/+$/, '');
const OAUTH_URL = process.env.COZMO_OAUTH_URL || 'https://oauth2.googleapis.com/token';

/* ---------- Firebase service account access token ---------- */
function loadKey() {
  let raw = process.env.FIREBASE_KEY || '';
  if (!raw) { for (const p of ['/etc/secrets/firebase.json', '/etc/secrets/firebase-key.json']) { try { raw = fs.readFileSync(p, 'utf8'); break; } catch (e) {} } }
  raw = String(raw).trim();
  if (!raw) return null;
  try { if (raw[0] !== '{') raw = Buffer.from(raw, 'base64').toString('utf8'); const k = JSON.parse(raw); if (k.client_email && k.private_key) return k; } catch (e) {}
  console.log('FIREBASE_KEY could not be read. Check that you pasted the whole file.');
  return null;
}
const KEY = loadKey();
const b64u = b => Buffer.from(b).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');

function request(url, opt, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url), mod = u.protocol === 'http:' ? http : https;
    const req = mod.request({ hostname: u.hostname, port: u.port || (u.protocol === 'http:' ? 80 : 443), path: u.pathname + u.search, method: opt.method || 'GET', headers: opt.headers || {} }, res => {
      const ch = []; res.on('data', d => ch.push(d)); res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(ch).toString('utf8') }));
    });
    req.setTimeout(15000, () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}
let tokenCache = { t: '', exp: 0 };
async function accessToken() {
  if (tokenCache.t && Date.now() < tokenCache.exp - 60000) return tokenCache.t;
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claim = b64u(JSON.stringify({ iss: KEY.client_email, scope: 'https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/userinfo.email', aud: OAUTH_URL, iat: now, exp: now + 3600 }));
  const sig = b64u(crypto.sign('RSA-SHA256', Buffer.from(head + '.' + claim), KEY.private_key));
  const r = await request(OAUTH_URL, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }, 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + head + '.' + claim + '.' + sig);
  let j = {}; try { j = JSON.parse(r.text); } catch (e) {}
  if (!j.access_token) throw new Error('Firebase sign-in failed: ' + r.text.slice(0, 200));
  tokenCache = { t: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 };
  return tokenCache.t;
}

/* ---------- Storage ---------- */
const mem = {};
function memPath(path, create) {
  const parts = path.split('/').filter(Boolean); let o = mem;
  for (let i = 0; i < parts.length - 1; i++) { if (typeof o[parts[i]] !== 'object' || o[parts[i]] === null) { if (!create) return null; o[parts[i]] = {}; } o = o[parts[i]]; }
  return { o, k: parts[parts.length - 1] };
}
const db = {
  mode: KEY ? 'firebase' : 'memory',
  async get(path) {
    if (!KEY) { const m = memPath(path, false); if (!m) return null; return m.k === undefined ? mem : (m.o[m.k] === undefined ? null : JSON.parse(JSON.stringify(m.o[m.k]))); }
    const r = await request(FB_URL + '/' + path + '.json?access_token=' + await accessToken(), {});
    if (r.status !== 200) throw new Error('database read ' + r.status + ' ' + r.text.slice(0, 120));
    return JSON.parse(r.text);
  },
  async set(path, val) {
    if (val === null || val === undefined) return db.del(path);
    if (!KEY) { const m = memPath(path, true); m.o[m.k] = JSON.parse(JSON.stringify(val)); return; }
    const r = await request(FB_URL + '/' + path + '.json?access_token=' + await accessToken(), { method: 'PUT', headers: { 'Content-Type': 'application/json' } }, JSON.stringify(val));
    if (r.status !== 200) throw new Error('database write ' + r.status + ' ' + r.text.slice(0, 120));
  },
  async del(path) {
    if (!KEY) { const m = memPath(path, false); if (m && m.o) delete m.o[m.k]; return; }
    const r = await request(FB_URL + '/' + path + '.json?access_token=' + await accessToken(), { method: 'DELETE' });
    if (r.status !== 200) throw new Error('database delete ' + r.status);
  }
};

/* ---------- Auth ---------- */
const SECRET = process.env.TOKEN_SECRET || (KEY ? crypto.createHash('sha256').update(KEY.private_key).digest('hex') : crypto.randomBytes(32).toString('hex'));
function makeToken(key) { const exp = Date.now() + 30 * 86400000, body = key + '.' + exp; return body + '.' + crypto.createHmac('sha256', SECRET).update(body).digest('hex'); }
function checkToken(t) {
  const p = String(t || '').split('.'); if (p.length !== 3 || !/^[a-z0-9_]{3,16}$/.test(p[0])) return null;
  const good = crypto.createHmac('sha256', SECRET).update(p[0] + '.' + p[1]).digest('hex');
  if (p[2].length !== good.length || !crypto.timingSafeEqual(Buffer.from(p[2]), Buffer.from(good))) return null;
  if (!(+p[1] > Date.now())) return null;
  return p[0];
}
function scrypt(pw, salt) { return new Promise((res, rej) => crypto.scrypt(pw, salt, 32, (e, k) => e ? rej(e) : res(k.toString('hex')))); }
const fails = {};
function tooMany(key) { const f = fails[key]; return f && f.n >= 8 && Date.now() - f.t < 600000; }
function noteFail(key) { const f = fails[key] || (fails[key] = { n: 0, t: 0 }); if (Date.now() - f.t > 600000) f.n = 0; f.n++; f.t = Date.now(); }

/* One write at a time, so numbering and name checks cannot race */
let chain = Promise.resolve();
function locked(fn) { const p = chain.then(fn, fn); chain = p.catch(() => {}); return p; }

const clean = (s, n) => String(s === undefined || s === null ? '' : s).replace(/[\u0000-\u001f\u007f]/g, '').slice(0, n);
const okId = s => /^[A-Za-z0-9_-]{1,40}$/.test(String(s));
const SAFE_CATS = ['Shirts', 'T-Shirts', 'Pants'], ALL_CATS = ['Shirts', 'T-Shirts', 'Pants', 'Hats', 'Gear', 'Faces'];
const jparse = s => { try { return JSON.parse(s); } catch (e) { return null; } };

/* ---------- Operations ---------- */
const ops = {
  async enter(m) {
    const name = clean(m.name, 16), key = name.toLowerCase(), pw = String(m.pw || '');
    if (!/^[A-Za-z0-9_]{3,16}$/.test(name)) return { err: 'Use 3 to 16 letters, numbers or underscores for the username.' };
    if (pw.length < 6 || pw.length > 100) return { err: 'Use at least 6 characters for the password.' };
    if (tooMany(key)) return { err: 'Too many wrong tries. Wait a few minutes.' };
    const acct = await db.get('accounts/' + key);
    if (acct) {
      const h = await scrypt(pw, Buffer.from(acct.salt, 'hex'));
      if (h !== acct.hash) { noteFail(key); return { err: m.create ? 'That username is taken online with a different password.' : 'Wrong password.' }; }
      return { token: makeToken(key), name: acct.name, adm: key === ADMIN_KEY ? 1 : 0 };
    }
    if (!m.create) return { err: 'noacct' };
    return locked(async () => {
      if (await db.get('accounts/' + key)) return { err: 'That username is taken online.' };
      const salt = crypto.randomBytes(16);
      await db.set('accounts/' + key, { name, salt: salt.toString('hex'), hash: await scrypt(pw, salt), created: Date.now() });
      await db.set('profiles/' + key, { name, bux: 150, tix: 1000, worn: {}, status: '' });
      return { token: makeToken(key), name, adm: key === ADMIN_KEY ? 1 : 0, fresh: 1 };
    });
  },

  async pull(m) {
    const since = Math.max(0, Math.floor(+m.since || 0)), have = (m.have && typeof m.have === 'object' && !Array.isArray(m.have)) ? m.have : {};
    const out = { items: [], delItems: [], games: [], gameIds: [], groups: [], deleted: [] };
    const items = (await db.get('items')) || {};
    Object.keys(items).forEach(k => {
      const it = items[k], seq = +k.slice(1);
      if (it.del) out.delItems.push(seq);
      if (seq > since) out.items.push({ seq, n: it.n || '', c: it.c || '', p: it.p || 0, d: it.d || '', col: it.col || '', dsn: it.dsn || '', by: it.by || '', del: it.del ? 1 : 0 });
    });
    out.items.sort((a, b) => a.seq - b.seq);
    const games = (await db.get('games')) || {};
    Object.keys(games).forEach(id => { out.gameIds.push(id); if (!(+have[id] >= (games[id].ts || 0))) { const g = jparse(games[id].j); if (g) { g.sts = games[id].ts || 0; out.games.push(g); } } });
    const groups = (await db.get('groups')) || {};
    Object.keys(groups).forEach(id => { const g = groups[id]; out.groups.push({ id, n: g.n, owner: g.owner, ownerKey: g.ownerKey, members: Object.keys(g.m || {}) }); });
    out.deleted = Object.keys((await db.get('deleted')) || {});
    return out;
  },

  async addItem(m, who) {
    const u = m.item || {};
    return locked(async () => {
      const seqN = ((await db.get('meta/seq')) || 0) + 1, id = 'i' + seqN;
      if (u.del) { await db.set('items/' + id, { del: 1 }); await db.set('meta/seq', seqN); return { seq: seqN }; }
      const isAdm = who === ADMIN_KEY, n = clean(u.n, 30).trim(), c = clean(u.c, 12);
      if (!n) return { err: 'Give your item a name.' };
      if ((isAdm ? ALL_CATS : SAFE_CATS).indexOf(c) < 0) return { err: 'You can only make shirts, t-shirts and pants.' };
      const p = Math.floor(+u.p); if (isNaN(p) || p < 0 || p > 9999) return { err: 'Price must be 0 to 9999.' };
      const all = (await db.get('items')) || {};
      for (const k in all) { if (all[k].n && all[k].n.toLowerCase() === n.toLowerCase()) return { err: 'An item with that name already exists.', dup: +k.slice(1) }; }
      const acct = await db.get('accounts/' + who);
      await db.set('items/' + id, { n, c, p, d: clean(u.d, 120), col: clean(u.col, 9), dsn: clean(u.dsn, 12), by: acct ? acct.name : who, bk: who });
      await db.set('meta/seq', seqN);
      return { seq: seqN };
    });
  },
  async delItem(m, who) {
    const seq = Math.floor(+m.seq), id = 'i' + seq;
    return locked(async () => {
      const it = await db.get('items/' + id); if (!it) return { err: 'No such item.' };
      if (it.del) return { ok: 1 };
      const acct = await db.get('accounts/' + who);
      if (who !== ADMIN_KEY && !(it.bk === who || (acct && it.by === acct.name))) return { err: 'You can only delete your own items.' };
      await db.set('items/' + id, { del: 1 }); return { ok: 1 };
    });
  },

  async putGame(m, who) {
    const g = m.game || {};
    if (!okId(g.id)) return { err: 'Bad game.' };
    const text = JSON.stringify(g); if (text.length > 700000) return { err: 'That game is too big to share.' };
    const old = await db.get('games/' + g.id), oldG = old && jparse(old.j);
    if (await db.get('deleted/' + g.id)) return { err: 'deleted' };
    if (who !== ADMIN_KEY && (g.byKey !== who || (oldG && oldG.byKey !== who))) return { err: 'That game belongs to someone else.' };
    const ts = Date.now(); await db.set('games/' + g.id, { j: text, ts }); return { ok: 1, ts };
  },
  async delGame(m, who) {
    if (!okId(m.id)) return { err: 'Bad id.' };
    const old = await db.get('games/' + m.id), g = old && jparse(old.j);
    if (g && who !== ADMIN_KEY && g.byKey !== who) return { err: 'That game belongs to someone else.' };
    await db.del('games/' + m.id); await db.set('deleted/' + m.id, 1); return { ok: 1 };
  },

  async putGroup(m, who) {
    const g = m.group || {};
    if (!okId(g.id)) return { err: 'Bad group.' };
    const old = await db.get('groups/' + g.id);
    if (await db.get('deleted/' + g.id)) return { err: 'deleted' };
    if (old && who !== ADMIN_KEY && old.ownerKey !== who) return { err: 'That group belongs to someone else.' };
    if (!old && g.ownerKey !== who && who !== ADMIN_KEY) return { err: 'Bad owner.' };
    const mem2 = old && old.m ? old.m : {}; mem2[g.ownerKey || who] = 1;
    await db.set('groups/' + g.id, { n: clean(g.n, 30), owner: clean(g.owner, 16), ownerKey: clean(g.ownerKey || who, 16), m: mem2 }); return { ok: 1 };
  },
  async joinGroup(m, who) {
    if (!okId(m.id) || !(await db.get('groups/' + m.id))) return { err: 'No such group.' };
    await db.set('groups/' + m.id + '/m/' + who, m.leave ? null : 1); return { ok: 1 };
  },
  async delGroup(m, who) {
    if (!okId(m.id)) return { err: 'Bad id.' };
    const g = await db.get('groups/' + m.id);
    if (g && who !== ADMIN_KEY && g.ownerKey !== who) return { err: 'That group belongs to someone else.' };
    await db.del('groups/' + m.id); await db.set('deleted/' + m.id, 1); return { ok: 1 };
  },

  async saveWallet(m, who) {
    const w = m.wallet; if (!w || typeof w !== 'object') return { err: 'Bad save.' };
    const text = JSON.stringify(w); if (text.length > 200000) return { err: 'Save too big.' };
    const acct = await db.get('accounts/' + who), ts = Date.now();
    await db.set('wallets/' + who, { j: text, ts });
    const worn = {}; if (w.worn && typeof w.worn === 'object') Object.keys(w.worn).forEach(k => { if (ALL_CATS.indexOf(k) >= 0 && Number.isInteger(w.worn[k])) worn[k] = w.worn[k]; });
    await db.set('profiles/' + who, { name: acct ? acct.name : who, bux: Math.floor(+w.bux) || 0, tix: Math.floor(+w.tix) || 0, worn, status: clean(w.status, 80) });
    return { ok: 1, ts };
  },
  async getWallet(m, who) {
    const r = await db.get('wallets/' + who); if (!r) return { none: 1 };
    return { wallet: jparse(r.j), ts: r.ts || 0 };
  },

  async search(m) {
    const q = clean(m.q, 16).toLowerCase(); if (!q) return { list: [] };
    const all = (await db.get('profiles')) || {}, out = [];
    Object.keys(all).forEach(k => { const p = all[k]; if (String(p.name || k).toLowerCase().indexOf(q) >= 0) out.push({ key: k, name: p.name || k, bux: p.bux || 0, tix: p.tix || 0, worn: p.worn || {}, status: p.status || '', exact: String(p.name || k).toLowerCase() === q }); });
    out.sort((a, b) => (b.exact ? 1 : 0) - (a.exact ? 1 : 0) || (a.name.toLowerCase() < b.name.toLowerCase() ? -1 : 1));
    return { list: out.slice(0, 20) };
  }
};
const PUBLIC = { enter: 1, pull: 1, search: 1 };

const hits = {};
function limited(ip) { const now = Date.now(), h = hits[ip] || (hits[ip] = []); while (h.length && now - h[0] > 60000) h.shift(); h.push(now); return h.length > 120; }
setInterval(() => { const now = Date.now(); Object.keys(hits).forEach(k => { if (!hits[k].length || now - hits[k][hits[k].length - 1] > 60000) delete hits[k]; }); }, 120000).unref();

function handle(req, res) {
  const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'POST, OPTIONS' };
  const send = (code, obj) => { res.writeHead(code, Object.assign({ 'Content-Type': 'application/json' }, cors)); res.end(JSON.stringify(obj)); };
  if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
  if (req.method !== 'POST') return send(405, { err: 'POST only' });
  if (limited(req.socket.remoteAddress || '?')) return send(429, { err: 'Slow down.' });
  const chunks = []; let size = 0;
  req.on('data', d => { size += d.length; if (size > 900000) { send(413, { err: 'Too big.' }); req.destroy(); } else chunks.push(d); });
  req.on('end', async () => {
    let m; try { m = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch (e) { return send(400, { err: 'Bad request.' }); }
    const f = m && ops[m.op]; if (!f) return send(400, { err: 'Unknown request.' });
    try {
      let who = null;
      if (!PUBLIC[m.op]) { who = checkToken(m.token); if (!who) return send(401, { err: 'login' }); }
      send(200, await f(m, who));
    } catch (e) { console.log('api error', m.op, String(e && e.message || e)); send(500, { err: 'The server had a problem. Try again.' }); }
  });
}
module.exports = { handle, db, ops, checkToken, makeToken };

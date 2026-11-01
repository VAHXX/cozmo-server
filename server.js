'use strict';
/*
 * Cozmo game server. No dependencies, just Node 16 or newer.
 *   node server.js            (listens on port 8080)
 *   PORT=9000 node server.js  (another port)
 *
 * Players join a game, get put on a server (a room) for that game, and see each other move
 * and chat. Each server holds up to MAX_PLAYERS; when all are full a new one is created.
 *
 * The server relays what players send. It does not yet decide hits, damage or rewards.
 */
const http = require('http');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 8080;
const MAX_PLAYERS = Number(process.env.MAX_PLAYERS) || 8;
const GAMES = ['baseplate', 'pizza', 'disaster', 'crossroads', 'heights'];
const TICK_MS = 100;
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
/* Words replaced with #### in chat. Add your own list here. */
const BLOCKED = ['badword'];

const rooms = new Map();          // "game:id" -> { game, id, players: Map(clientId -> Client) }
const counters = {};              // game -> last server number used
let nextClientId = 1;

function clean(str, max) { return String(str === undefined ? '' : str).replace(/[\u0000-\u001f\u007f]/g, '').slice(0, max); }
function num(v, lo, hi, dflt) { v = Number(v); return Number.isFinite(v) ? Math.max(lo, Math.min(hi, v)) : dflt; }
function filterChat(text) {
  let out = text;
  for (const w of BLOCKED) { if (w) out = out.replace(new RegExp(w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), '####'); }
  return out;
}
/* What a player looks like (colours and designs only). Anything else is dropped. */
const HEX = /^#[0-9a-fA-F]{6}$/, WORD = /^[a-z]{1,12}$/;
function int24(v) { v = Math.floor(Number(v)); return Number.isFinite(v) && v >= 0 && v <= 0xffffff ? v : 0; }
function cleanLook(l) {
  if (!l || typeof l !== 'object') return { v: 2 };
  const o = { v: 2 };
  ['shirt', 'sleeves', 'pants', 'pants2', 'hatColor'].forEach(k => { o[k] = int24(l[k]); });
  o.hat = typeof l.hat === 'string' && WORD.test(l.hat) ? l.hat : false;
  o.face = typeof l.face === 'string' && WORD.test(l.face) ? l.face : null;
  const d = l.shirtD;
  o.shirtD = d && typeof d === 'object' && HEX.test(String(d.col)) ? { k: clean(d.k, 10), col: d.col, dsn: WORD.test(String(d.dsn)) ? d.dsn : 'plain', ini: clean(d.ini, 1) } : null;
  const p = l.pantsD;
  o.pantsD = p && typeof p === 'object' && HEX.test(String(p.col)) ? { col: p.col, dsn: WORD.test(String(p.dsn)) ? p.dsn : 'plain' } : null;
  return o;
}
function roomsFor(game) { return Array.from(rooms.values()).filter(r => r.game === game); }
function listFor(game) { return roomsFor(game).map(r => ({ id: r.id, n: r.players.size, max: MAX_PLAYERS })); }
function createRoom(game) {
  counters[game] = (counters[game] || 0) + 1;
  const room = { game, id: counters[game], players: new Map() };
  rooms.set(game + ':' + room.id, room);
  return room;
}

/* ---- Minimal WebSocket framing ---- */
function encode(text) {
  const body = Buffer.from(text, 'utf8'), n = body.length;
  let head;
  if (n < 126) head = Buffer.from([0x81, n]);
  else if (n < 65536) { head = Buffer.alloc(4); head[0] = 0x81; head[1] = 126; head.writeUInt16BE(n, 2); }
  else { head = Buffer.alloc(10); head[0] = 0x81; head[1] = 127; head.writeBigUInt64BE(BigInt(n), 2); }
  return Buffer.concat([head, body]);
}
function parseFrame(buf) {
  if (buf.length < 2) return null;
  const fin = (buf[0] & 0x80) !== 0, op = buf[0] & 0x0f, masked = (buf[1] & 0x80) !== 0;
  let len = buf[1] & 0x7f, off = 2;
  if (len === 126) { if (buf.length < 4) return null; len = buf.readUInt16BE(2); off = 4; }
  else if (len === 127) { if (buf.length < 10) return null; const big = buf.readBigUInt64BE(2); if (big > 1000000n) return { bad: true }; len = Number(big); off = 10; }
  if (len > 20000) return { bad: true };
  const maskLen = masked ? 4 : 0;
  if (buf.length < off + maskLen + len) return null;
  const payload = Buffer.from(buf.subarray(off + maskLen, off + maskLen + len));
  if (masked) { const m = buf.subarray(off, off + 4); for (let i = 0; i < payload.length; i++) payload[i] ^= m[i & 3]; }
  return { fin, op, payload, total: off + maskLen + len };
}

class Client {
  constructor(socket) {
    this.socket = socket; this.buf = Buffer.alloc(0); this.id = nextClientId++;
    this.room = null; this.name = ''; this.key = ''; this.adm = 0; this.token = ''; this.joining = false; this.look = { v: 2 };
    this.s = { x: 0, y: 0, z: 0, ry: 0, tool: '', tl: '', tc: '', mv: 0, air: 0 };
    this.parts = null; this.lastSeen = Date.now(); this.lastState = 0; this.lastChat = 0; this.dead = false;
    socket.setNoDelay(true);
    socket.on('data', d => this.onData(d));
    socket.on('close', () => this.kill());
    socket.on('error', () => this.kill());
  }
  send(obj) { if (!this.dead) { try { this.socket.write(encode(JSON.stringify(obj))); } catch (e) { this.kill(); } } }
  onData(d) {
    this.buf = Buffer.concat([this.buf, d]);
    if (this.buf.length > 80000) return this.kill();
    for (;;) {
      const f = parseFrame(this.buf);
      if (!f) break;
      if (f.bad) return this.kill();
      this.buf = this.buf.subarray(f.total);
      this.onFrame(f);
      if (this.dead) return;
    }
  }
  onFrame(f) {
    this.lastSeen = Date.now();
    if (f.op === 8) { try { this.socket.write(Buffer.from([0x88, 0])); } catch (e) {} return this.kill(); }
    if (f.op === 9) { try { this.socket.write(Buffer.concat([Buffer.from([0x8a, f.payload.length]), f.payload])); } catch (e) {} return; }
    if (f.op === 1 || f.op === 2) { this.parts = [f.payload]; } else if (f.op === 0 && this.parts) { this.parts.push(f.payload); } else return;
    if (!f.fin) return;
    const text = Buffer.concat(this.parts).toString('utf8'); this.parts = null;
    let msg; try { msg = JSON.parse(text); } catch (e) { return; }
    if (msg && typeof msg === 'object') this.onMessage(msg);
  }
  onMessage(m) {
    if (m.t === 'list') {
      const game = GAMES.includes(m.game) ? m.game : 'baseplate';
      return this.send({ t: 'servers', game, list: listFor(game), max: MAX_PLAYERS });
    }
    if (m.t === 'join') return this.join(m);
    if (m.t === 'ban') return this.banPlayer(m);
    if (!this.room) return;
    if (m.t === 'state') {
      const now = Date.now(); if (now - this.lastState < 30) return; this.lastState = now;
      const s = this.s;
      s.x = num(m.x, -600, 600, s.x); s.y = num(m.y, -100, 300, s.y); s.z = num(m.z, -600, 600, s.z);
      s.ry = num(m.ry, -10, 10, s.ry); s.tool = ['sword', 'bow', 'torch'].includes(m.tool) ? m.tool : '';
      s.tl = typeof m.tl === 'string' && WORD.test(m.tl) ? m.tl : ''; s.tc = typeof m.tc === 'string' && HEX.test(m.tc) ? m.tc : '';
      s.mv = m.mv ? 1 : 0; s.air = m.air ? 1 : 0;
    } else if (m.t === 'chat') {
      const now = Date.now(); if (now - this.lastChat < 800) return; this.lastChat = now;
      const text = filterChat(clean(m.text, 80)).trim(); if (!text) return;
      this.broadcast({ t: 'chat', id: this.id, name: this.name, text });
    } else if (m.t === 'leave') { this.leave(); }
  }
  async join(m) {
    if (this.joining) return; this.joining = true;
    try {
      const game = GAMES.includes(m.game) ? m.game : null;
      if (!game) return this.send({ t: 'error', text: 'Unknown game.' });
      let who = null;
      try { who = await api.authInfo(m.token); } catch (e) { return this.send({ t: 'error', text: 'The server could not check your login. Try again.' }); }
      if (!who) return this.send({ t: 'error', text: 'Please log in online (or you may be banned) to play with others.' });
      if (this.dead) return;
      this.key = who.key; this.adm = who.adm; this.token = String(m.token);
      this.joinRoom(m, game, who.name.replace(/[^A-Za-z0-9_]/g, ''));
    } finally { this.joining = false; }
  }
  async banPlayer(m) {
    if (!this.room) return;
    let me = null; try { me = await api.authInfo(this.token); } catch (e) {}
    if (!me || !me.adm) return this.send({ t: 'error', text: 'Only admins can ban.' });
    const t = this.room && this.room.players.get(Number(m.id));
    if (!t || !t.key) return this.send({ t: 'error', text: 'Player not found.' });
    const r = await api.ops.admin({ action: 'ban', key: t.key }, me.key, me.adm);
    if (r.err) return this.send({ t: 'error', text: r.err });
    this.send({ t: 'banok', name: t.name });
  }
  joinRoom(m, game, name) {
    if (name.length < 1) return this.send({ t: 'error', text: 'Bad name.' });
    this.leave();
    let room = null;
    if (m.server === 'new') room = createRoom(game);
    else if (Number.isInteger(m.server)) { room = rooms.get(game + ':' + m.server); if (!room) return this.send({ t: 'error', text: 'That server is gone.' }); }
    else {
      const open = roomsFor(game).filter(r => r.players.size < MAX_PLAYERS).sort((a, b) => b.players.size - a.players.size);
      room = open[0] || createRoom(game);
    }
    if (room.players.size >= MAX_PLAYERS) return this.send({ t: 'error', text: 'That server is full.' });
    this.name = name;
    this.look = cleanLook(m.look);
    this.room = room; room.players.set(this.id, this);
    const others = [];
    room.players.forEach(p => { if (p !== this) others.push(this.snapshot(p)); });
    this.send({ t: 'joined', id: this.id, server: room.id, max: MAX_PLAYERS, players: others });
    this.broadcast({ t: 'join', p: this.snapshot(this) });
    log(name + ' joined ' + game + ' #' + room.id + ' (' + room.players.size + '/' + MAX_PLAYERS + ')');
  }
  snapshot(p) { return { id: p.id, name: p.name, look: p.look, x: p.s.x, y: p.s.y, z: p.s.z, ry: p.s.ry, tool: p.s.tool, tl: p.s.tl, tc: p.s.tc }; }
  broadcast(obj) { if (this.room) this.room.players.forEach(p => { if (p !== this) p.send(obj); }); }
  leave() {
    const room = this.room; if (!room) return;
    room.players.delete(this.id); this.room = null;
    room.players.forEach(p => p.send({ t: 'leave', id: this.id }));
    if (room.players.size === 0) rooms.delete(room.game + ':' + room.id);
    log(this.name + ' left ' + room.game + ' #' + room.id);
  }
  kill() { if (this.dead) return; this.leave(); this.dead = true; try { this.socket.destroy(); } catch (e) {} }
}

function log(s) { console.log(new Date().toISOString().slice(11, 19) + '  ' + s); }

const api = require('./api');
const server = http.createServer((req, res) => {
  if (req.url.split('?')[0] === '/api') return api.handle(req, res);
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.url === '/status') {
    const out = {}; rooms.forEach(r => { (out[r.game] = out[r.game] || []).push({ id: r.id, players: r.players.size, max: MAX_PLAYERS }); });
    res.setHeader('Content-Type', 'application/json'); return res.end(JSON.stringify(out));
  }
  res.setHeader('Content-Type', 'text/plain'); res.end('Cozmo game server is running. Storage: ' + api.db.mode + '\n');
});
server.on('upgrade', (req, socket) => {
  const key = req.headers['sec-websocket-key'];
  if (!key || String(req.headers.upgrade).toLowerCase() !== 'websocket') { socket.destroy(); return; }
  const accept = crypto.createHash('sha1').update(key + GUID).digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  const c = new Client(socket); clients.add(c); socket.on('close', () => clients.delete(c));
});
const clients = new Set();
api.hooks.onBan = key => { clients.forEach(c => { if (c.key === key) { c.send({ t: 'banned' }); setTimeout(() => c.kill(), 400); } }); };

setInterval(() => {
  rooms.forEach(room => {
    if (room.players.size < 2) return;
    const s = [];
    room.players.forEach(p => s.push([p.id, +p.s.x.toFixed(2), +p.s.y.toFixed(2), +p.s.z.toFixed(2), +p.s.ry.toFixed(2), p.s.tool, p.s.mv, p.s.air, p.s.tl, p.s.tc]));
    room.players.forEach(p => p.send({ t: 'peers', s }));
  });
}, TICK_MS);
setInterval(() => { const now = Date.now(); clients.forEach(c => { if (now - c.lastSeen > 45000) c.kill(); }); }, 15000);

server.listen(PORT, () => log('Cozmo game server listening on port ' + PORT + ' (max ' + MAX_PLAYERS + ' players per server)'));

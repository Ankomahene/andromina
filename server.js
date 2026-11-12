'use strict';
// Zero-dependency server: static pages + JSON API + file-based storage.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Load a local .env file (never committed) so secrets stay out of the code.
try {
  for (const line of require('fs').readFileSync(require('path').join(__dirname, '.env'), 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^(['"])(.*)\1$/, '$2');
  }
} catch {}

const PORT = process.env.PORT || 3000;
const OWNER = process.env.OWNER_NAME || 'Andromina';
const PUBLIC = path.join(__dirname, 'public');

// Where data lives. On Railway, attach a Volume mounted at /data so it survives redeploys.
const DATA_DIR = process.env.DATA_DIR || (fs.existsSync('/data') ? '/data' : path.join(__dirname, 'data'));
fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_FILE = path.join(DATA_DIR, 'db.json');

/* ---------- tiny storage layer ---------- */
const scryptHash = (pin, salt) => crypto.scryptSync(String(pin), salt, 32).toString('hex');
const normPhone = (p) => {
  let d = String(p || '').replace(/\D/g, '');
  if (d.startsWith('233') && d.length >= 12) d = '0' + d.slice(3); // +233 -> 0
  return d;
};

let db;
function load() {
  try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch { db = null; }
  if (!db) {
    if (!process.env.ADMIN_PHONE || !process.env.ADMIN_PIN) {
      console.error('Missing ADMIN_PHONE and/or ADMIN_PIN. Set them as environment variables (see .env.example).');
      process.exit(1);
    }
    const salt = crypto.randomBytes(16).toString('hex');
    db = {
      secret: crypto.randomBytes(32).toString('hex'),
      admin: {
        phone: normPhone(process.env.ADMIN_PHONE),
        salt,
        hash: scryptHash(process.env.ADMIN_PIN, salt),
        ver: 1,
      },
      messages: [],
    };
    save();
  }
}
function save() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DB_FILE);
}
load();

/* ---------- helpers ---------- */
const sign = (s) => crypto.createHmac('sha256', db.secret).update(s).digest('base64url');
function makeToken() {
  const body = Buffer.from(JSON.stringify({ exp: Date.now() + 30 * 864e5, v: db.admin.ver })).toString('base64url');
  return body + '.' + sign(body);
}
function checkToken(tok) {
  if (!tok) return false;
  const [body, sig] = tok.split('.');
  if (!body || !sig) return false;
  const good = sign(body);
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return false;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p.exp > Date.now() && p.v === db.admin.ver;
  } catch { return false; }
}
const cookies = (req) => Object.fromEntries((req.headers.cookie || '').split(';').map((c) => c.trim().split(/=(.*)/s).slice(0, 2)).filter((x) => x[0]));
const isAuthed = (req) => checkToken(cookies(req).sid);
const ip = (req) => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
const isHttps = (req) => (req.headers['x-forwarded-proto'] || '').split(',')[0] === 'https';
const baseUrl = (req) => process.env.BASE_URL || `${isHttps(req) ? 'https' : 'http'}://${req.headers['x-forwarded-host'] || req.headers.host}`;

// Simple in-memory rate limiter (sender IPs are never written to disk).
const hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < windowMs);
  if (arr.length >= max) { hits.set(key, arr); return true; }
  arr.push(now); hits.set(key, arr); return false;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some((t) => now - t < 36e5)) hits.delete(k); }, 6e5).unref();

const json = (res, code, obj, extra = {}) => {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra });
  res.end(JSON.stringify(obj));
};
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > 20000) { reject(new Error('too big')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); } catch { reject(new Error('bad json')); } });
    req.on('error', reject);
  });
}
const clean = (s, max) => String(s || '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '').trim().slice(0, max);

/* ---------- static ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json', '.txt': 'text/plain' };
function sendPage(req, res, file, noindex) {
  let html = fs.readFileSync(path.join(PUBLIC, file), 'utf8')
    .replace(/\{\{BASE\}\}/g, baseUrl(req)).replace(/\{\{OWNER\}\}/g, OWNER).replace(/\{\{INITIAL\}\}/g, OWNER.trim().charAt(0).toUpperCase());
  res.writeHead(200, { 'Content-Type': MIME['.html'], 'Cache-Control': 'no-cache', ...(noindex ? { 'X-Robots-Tag': 'noindex, nofollow' } : {}) });
  res.end(html);
}
function sendStatic(req, res, pathname) {
  const file = path.normalize(path.join(PUBLIC, pathname));
  if (!file.startsWith(PUBLIC) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404); return res.end('Not found'); }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'public, max-age=3600' });
  fs.createReadStream(file).pipe(res);
}

/* ---------- routes ---------- */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'DENY');

  try {
    if (req.method === 'GET') {
      if (p === '/' || p === '/index.html') return sendPage(req, res, 'index.html');
      if (p === '/admin' || p === '/admin/') return sendPage(req, res, 'admin.html', true);
      if (p === '/healthz') return json(res, 200, { ok: true });
      if (p === '/robots.txt') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('User-agent: *\nDisallow: /admin\nDisallow: /api/\n'); }
      if (p === '/api/me') return json(res, 200, { authed: isAuthed(req), owner: OWNER });
      if (p === '/api/messages') {
        if (!isAuthed(req)) return json(res, 401, { error: 'Not logged in' });
        return json(res, 200, { messages: [...db.messages].reverse() });
      }
      return sendStatic(req, res, p);
    }

    // All writes must be JSON (blocks cross-site form posts).
    if (!(req.headers['content-type'] || '').startsWith('application/json')) return json(res, 415, { error: 'Bad request' });

    if (req.method === 'POST' && p === '/api/messages') {
      const b = await readBody(req);
      if (b.website) return json(res, 200, { ok: true }); // honeypot: pretend success to bots
      if (limited('msg:' + ip(req), 6, 10 * 60e3)) return json(res, 429, { error: "Whoa, that's a lot of messages! Try again in a few minutes." });
      const text = clean(b.text, 1500);
      if (text.length < 2) return json(res, 400, { error: 'Write a little something first 💬' });
      db.messages.push({ id: crypto.randomBytes(6).toString('hex'), text, name: clean(b.name, 40), createdAt: Date.now(), read: false });
      save();
      return json(res, 200, { ok: true });
    }

    if (req.method === 'POST' && p === '/api/login') {
      if (limited('login:' + ip(req), 8, 15 * 60e3)) return json(res, 429, { error: 'Too many attempts. Please wait a few minutes.' });
      const b = await readBody(req);
      const a = db.admin;
      const okPhone = normPhone(b.phone) === a.phone;
      const h = scryptHash(String(b.pin || ''), a.salt);
      const okPin = crypto.timingSafeEqual(Buffer.from(h), Buffer.from(a.hash));
      if (!okPhone || !okPin) return json(res, 401, { error: 'Phone number or PIN is incorrect' });
      return json(res, 200, { ok: true }, { 'Set-Cookie': `sid=${makeToken()}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${30 * 86400}${isHttps(req) ? '; Secure' : ''}` });
    }

    if (req.method === 'POST' && p === '/api/logout') {
      return json(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0' });
    }

    // ---- authed below ----
    if (!isAuthed(req)) return json(res, 401, { error: 'Not logged in' });

    if (req.method === 'POST' && p === '/api/change-pin') {
      const b = await readBody(req);
      const a = db.admin;
      if (!crypto.timingSafeEqual(Buffer.from(scryptHash(String(b.currentPin || ''), a.salt)), Buffer.from(a.hash))) return json(res, 400, { error: 'Current PIN is incorrect' });
      const np = String(b.newPin || '');
      if (!/^\d{4,8}$/.test(np)) return json(res, 400, { error: 'New PIN must be 4–8 digits' });
      a.salt = crypto.randomBytes(16).toString('hex');
      a.hash = scryptHash(np, a.salt);
      a.ver += 1; // signs out every other device
      save();
      return json(res, 200, { ok: true }, { 'Set-Cookie': `sid=${makeToken()}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${30 * 86400}${isHttps(req) ? '; Secure' : ''}` });
    }

    let m;
    if (req.method === 'POST' && (m = p.match(/^\/api\/messages\/([a-f0-9]+)\/read$/))) {
      const b = await readBody(req);
      const msg = db.messages.find((x) => x.id === m[1]);
      if (!msg) return json(res, 404, { error: 'Not found' });
      msg.read = b.read !== false; save();
      return json(res, 200, { ok: true });
    }
    if (req.method === 'POST' && p === '/api/messages/read-all') {
      db.messages.forEach((x) => (x.read = true)); save();
      return json(res, 200, { ok: true });
    }
    if (req.method === 'DELETE' && (m = p.match(/^\/api\/messages\/([a-f0-9]+)$/))) {
      db.messages = db.messages.filter((x) => x.id !== m[1]); save();
      return json(res, 200, { ok: true });
    }
    return json(res, 404, { error: 'Not found' });
  } catch (e) {
    return json(res, 400, { error: 'Something went wrong' });
  }
});

server.listen(PORT, '0.0.0.0', () => console.log(`Listening on :${PORT} · data in ${DATA_DIR}`));

// Consistency Crew API: accounts, sessions and a small document store.
// Coaches own a "scope"; every document lives inside one coach's scope.
// Clients can read the coach's exercise library and settings, and read/write only
// their own members/<uid>/... documents. Nothing else in the scope is visible to them.

const COOKIE = 'cc_s';
const SESSION_DAYS = 60;
// The free Workers plan allows ~10 ms of CPU per request, so the iteration count is kept
// modest and every password is first mixed with a secret pepper (PEPPER) that never
// lives in the database. A leaked database alone is not enough to test guesses offline.
const PBKDF2_ITER = 20000;
const enc = new TextEncoder();

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers } });
const err = (status, message) => json({ error: message }, status);

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const randBytes = (n) => crypto.getRandomValues(new Uint8Array(n));
const newId = () => hex(randBytes(12));
const sha256 = async (s) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));

let PEPPER_KEY = null;
async function hashPassword(password, saltB64) {
  const salt = saltB64 ? Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0)) : randBytes(16);
  const pw = enc.encode(String(password).slice(0, 256));
  const peppered = PEPPER_KEY ? new Uint8Array(await crypto.subtle.sign('HMAC', PEPPER_KEY, pw)) : pw;
  const key = await crypto.subtle.importKey('raw', peppered, 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITER }, key, 256);
  return { hash: b64(bits), salt: b64(salt) };
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

const cleanEmail = (e) => String(e || '').trim().toLowerCase();
const validEmail = (e) => /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/.test(e);
const cleanName = (n) => String(n || '').replace(/\s+/g, ' ').trim().slice(0, 60);
const COLORS = ['#188e5c', '#1d4ed8', '#d92d20', '#f5a300', '#7c3aed', '#0e7490', '#c2410c', '#be185d'];

function getCookie(req, name) {
  const c = req.headers.get('cookie') || '';
  for (const part of c.split(/;\s*/)) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i) === name) return decodeURIComponent(part.slice(i + 1));
  }
  return null;
}
const sessionCookie = (token, maxAge) =>
  `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

async function currentUser(req, env) {
  const tok = getCookie(req, COOKIE);
  if (!tok || !/^[a-f0-9]{64}$/.test(tok)) return null;
  const th = await sha256(tok);
  const row = await env.DB.prepare(
    'SELECT u.id,u.email,u.name,u.role,u.coach_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?'
  ).bind(th, Date.now()).first();
  return row || null;
}
async function startSession(env, userId) {
  const token = hex(randBytes(32));
  const expires = Date.now() + SESSION_DAYS * 864e5;
  await env.DB.prepare('INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (?,?,?)').bind(await sha256(token), userId, expires).run();
  return sessionCookie(token, SESSION_DAYS * 86400);
}
const publicUser = (u) => ({ id: u.id, email: u.email, name: u.name, role: u.role, coachId: u.coach_id || null });

// ---------- permissions ----------
const ID = '[A-Za-z0-9_-]{1,64}';
const COL_RE = new RegExp(`^(exercises|clients|workouts|sessions|members|private|settings|archives|members/${ID}/(workouts|sessions))$`);
function scopeOf(u) { return u.role === 'coach' ? u.id : u.coach_id; }
function canRead(u, col, id) {
  if (u.role === 'coach') return true;
  if (col === 'exercises') return true;
  if (col === 'settings') return id === undefined || id === 'app';
  if (col === 'members') return id === u.id;
  return col === `members/${u.id}/workouts` || col === `members/${u.id}/sessions`;
}
function canWrite(u, col) {
  if (u.role === 'coach') return true;
  return col === `members/${u.id}/workouts` || col === `members/${u.id}/sessions`;
}
function splitDocPath(path) {
  const p = String(path || '').split('/');
  if (p.length < 2) return null;
  const id = p.pop();
  return { col: p.join('/'), id };
}
const validId = (id) => new RegExp(`^${ID}$`).test(id || '');

// ---------- rate limit (login / signup) ----------
async function limited(env, key, max, windowMs) {
  const now = Date.now();
  const row = await env.DB.prepare('SELECT n,since FROM attempts WHERE k=?').bind(key).first();
  if (row && now - row.since < windowMs && row.n >= max) return true;
  if (!row || now - row.since >= windowMs) await env.DB.prepare('INSERT OR REPLACE INTO attempts (k,n,since) VALUES (?,1,?)').bind(key, now).run();
  else await env.DB.prepare('UPDATE attempts SET n=n+1 WHERE k=?').bind(key).run();
  return false;
}
const clearLimit = (env, key) => env.DB.prepare('DELETE FROM attempts WHERE k=?').bind(key).run();

async function readBody(req) {
  try { return await req.json(); } catch { return {}; }
}

// ---------- handlers ----------
async function api(req, env, url) {
  const path = url.pathname.slice(4); // after /api
  const method = req.method;
  if (method !== 'GET' && method !== 'HEAD') {
    const origin = req.headers.get('origin');
    if (origin && origin !== url.origin) return err(403, 'Bad origin');
  }

  if (path === '/coaches' && method === 'GET') {
    const r = await env.DB.prepare("SELECT id,name,brand FROM users WHERE role='coach' ORDER BY created_at").all();
    return json({ coaches: r.results.map((c) => ({ id: c.id, name: c.name, brand: c.brand || '' })) });
  }

  if (path === '/setup-state' && method === 'GET') {
    const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE role='coach'").first();
    return json({ hasCoach: r.n > 0 });
  }

  if (path === '/coach-setup' && method === 'POST') {
    const b = await readBody(req);
    if (!env.SETUP_CODE || !safeEqual(String(b.code || '').trim(), env.SETUP_CODE)) {
      if (await limited(env, 'setup', 10, 36e5)) return err(429, 'Too many tries. Wait an hour.');
      return err(403, 'That setup code is not right.');
    }
    const email = cleanEmail(b.email), name = cleanName(b.name);
    if (!validEmail(email)) return err(400, 'Enter a valid email.');
    if (!name) return err(400, 'Enter your name.');
    if (String(b.password || '').length < 8) return err(400, 'Use at least 8 characters for your password.');
    if (await env.DB.prepare('SELECT 1 FROM users WHERE email=?').bind(email).first()) return err(409, 'That email already has an account.');
    const id = newId();
    const { hash, salt } = await hashPassword(String(b.password));
    await env.DB.prepare("INSERT INTO users (id,email,name,role,coach_id,brand,pass_hash,pass_salt,created_at) VALUES (?,?,?,'coach',NULL,?,?,?,?)")
      .bind(id, email, name, cleanName(b.brand) || 'Consistency Crew', hash, salt, Date.now()).run();
    const cookie = await startSession(env, id);
    return json({ user: { id, email, name, role: 'coach', coachId: null } }, 200, { 'set-cookie': cookie });
  }

  if (path === '/signup' && method === 'POST') {
    const b = await readBody(req);
    const ip = req.headers.get('cf-connecting-ip') || 'x';
    if (await limited(env, 'signup:' + ip, 8, 36e5)) return err(429, 'Too many sign-ups from here. Try again later.');
    const email = cleanEmail(b.email), name = cleanName(b.name);
    if (!name) return err(400, 'Enter your name.');
    if (!validEmail(email)) return err(400, 'Enter a valid email.');
    if (String(b.password || '').length < 8) return err(400, 'Use at least 8 characters for your password.');
    const coach = await env.DB.prepare("SELECT id FROM users WHERE id=? AND role='coach'").bind(String(b.coachId || '')).first();
    if (!coach) return err(400, 'Pick your coach.');
    if (await env.DB.prepare('SELECT 1 FROM users WHERE email=?').bind(email).first()) return err(409, 'That email already has an account. Log in instead.');
    const id = newId();
    const { hash, salt } = await hashPassword(String(b.password));
    const now = Date.now();
    const cid = 'c' + newId().slice(0, 10);
    const color = COLORS[Math.floor(Math.random() * COLORS.length)];
    const client = { name, perWeek: 3, color, uid: id, email, linkedAt: now, joinedAt: now, updatedAt: now };
    const profile = { cid, name, perWeek: 3, color, archiveId: null, linkedAt: now };
    await env.DB.batch([
      env.DB.prepare("INSERT INTO users (id,email,name,role,coach_id,brand,pass_hash,pass_salt,created_at) VALUES (?,?,?,'client',?,NULL,?,?,?)")
        .bind(id, email, name, coach.id, hash, salt, now),
      env.DB.prepare('INSERT OR REPLACE INTO docs (scope,col,id,data,updated_at) VALUES (?,?,?,?,?)').bind(coach.id, 'clients', cid, JSON.stringify(client), now),
      env.DB.prepare('INSERT OR REPLACE INTO docs (scope,col,id,data,updated_at) VALUES (?,?,?,?,?)').bind(coach.id, 'members', id, JSON.stringify(profile), now),
    ]);
    const cookie = await startSession(env, id);
    return json({ user: { id, email, name, role: 'client', coachId: coach.id } }, 200, { 'set-cookie': cookie });
  }

  if (path === '/login' && method === 'POST') {
    const b = await readBody(req);
    const email = cleanEmail(b.email);
    const key = 'login:' + email;
    if (await limited(env, key, 10, 15 * 6e4)) return err(429, 'Too many tries. Wait 15 minutes and try again.');
    const u = await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
    if (!u) { await hashPassword('x'); return err(401, 'Email or password is wrong.'); }
    const { hash } = await hashPassword(String(b.password || ''), u.pass_salt);
    if (!safeEqual(hash, u.pass_hash)) return err(401, 'Email or password is wrong.');
    await clearLimit(env, key);
    const cookie = await startSession(env, u.id);
    return json({ user: publicUser(u) }, 200, { 'set-cookie': cookie });
  }

  if (path === '/logout' && method === 'POST') {
    const tok = getCookie(req, COOKIE);
    if (tok) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha256(tok)).run();
    return json({ ok: true }, 200, { 'set-cookie': sessionCookie('', 0) });
  }

  const me = await currentUser(req, env);
  if (path === '/me' && method === 'GET') {
    if (!me) return json({ user: null });
    let coach = null;
    if (me.coach_id) coach = await env.DB.prepare('SELECT name,brand FROM users WHERE id=?').bind(me.coach_id).first();
    return json({ user: publicUser(me), coach });
  }
  if (!me) return err(401, 'Please log in.');

  if (path === '/password' && method === 'POST') {
    const b = await readBody(req);
    const u = await env.DB.prepare('SELECT pass_hash,pass_salt FROM users WHERE id=?').bind(me.id).first();
    const { hash } = await hashPassword(String(b.current || ''), u.pass_salt);
    if (!safeEqual(hash, u.pass_hash)) return err(401, 'Your current password is wrong.');
    if (String(b.password || '').length < 8) return err(400, 'Use at least 8 characters.');
    const n = await hashPassword(String(b.password));
    await env.DB.prepare('UPDATE users SET pass_hash=?,pass_salt=? WHERE id=?').bind(n.hash, n.salt, me.id).run();
    return json({ ok: true });
  }

  if (path === '/reset-client' && method === 'POST') {
    if (me.role !== 'coach') return err(403, 'Only your coach can do that.');
    const b = await readBody(req);
    const u = await env.DB.prepare("SELECT id FROM users WHERE id=? AND role='client' AND coach_id=?").bind(String(b.uid || ''), me.id).first();
    if (!u) return err(404, 'That client has no account.');
    const words = ['lift', 'squat', 'press', 'row', 'pull', 'run', 'core', 'grip', 'plate', 'rack', 'bench', 'sprint'];
    const pick = () => words[crypto.getRandomValues(new Uint32Array(1))[0] % words.length];
    const temp = `${pick()}-${pick()}-${(crypto.getRandomValues(new Uint32Array(1))[0] % 9000) + 1000}`;
    const n = await hashPassword(temp);
    await env.DB.batch([
      env.DB.prepare('UPDATE users SET pass_hash=?,pass_salt=? WHERE id=?').bind(n.hash, n.salt, u.id),
      env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(u.id),
    ]);
    return json({ temp });
  }

  // ----- documents -----
  const scope = scopeOf(me);
  if (!scope) return err(403, 'No coach on this account.');

  if (path === '/col' && method === 'GET') {
    const col = url.searchParams.get('path') || '';
    if (!COL_RE.test(col)) return err(400, 'Bad path');
    if (!canRead(me, col)) return err(403, 'Not allowed');
    if (me.role !== 'coach' && col === 'members') return err(403, 'Not allowed');
    const r = await env.DB.prepare('SELECT id,data FROM docs WHERE scope=? AND col=?').bind(scope, col).all();
    return json({ docs: r.results.map((d) => ({ id: d.id, data: JSON.parse(d.data) })) });
  }

  if (path === '/doc') {
    const sp = splitDocPath(url.searchParams.get('path'));
    if (!sp || !COL_RE.test(sp.col) || !validId(sp.id)) return err(400, 'Bad path');
    if (method === 'GET') {
      let ok = canRead(me, sp.col, sp.id);
      if (!ok && sp.col === 'archives' && me.role === 'client') {
        // A client may read the training history archive of the profile they are linked to.
        const m = await env.DB.prepare("SELECT data FROM docs WHERE scope=? AND col='members' AND id=?").bind(scope, me.id).first();
        ok = !!m && JSON.parse(m.data).cid === sp.id;
      }
      if (!ok) return err(403, 'Not allowed');
      const d = await env.DB.prepare('SELECT data FROM docs WHERE scope=? AND col=? AND id=?').bind(scope, sp.col, sp.id).first();
      return json({ exists: !!d, data: d ? JSON.parse(d.data) : null });
    }
    if (!canWrite(me, sp.col)) return err(403, 'Not allowed');
    if (method === 'PUT') {
      const text = await req.text();
      if (text.length > 900000) return err(413, 'Too big');
      let data;
      try { data = JSON.parse(text); } catch { return err(400, 'Bad JSON'); }
      if (!data || typeof data !== 'object' || Array.isArray(data)) return err(400, 'Bad JSON');
      await env.DB.prepare('INSERT OR REPLACE INTO docs (scope,col,id,data,updated_at) VALUES (?,?,?,?,?)')
        .bind(scope, sp.col, sp.id, JSON.stringify(data), Date.now()).run();
      return json({ ok: true });
    }
    if (method === 'DELETE') {
      await env.DB.prepare('DELETE FROM docs WHERE scope=? AND col=? AND id=?').bind(scope, sp.col, sp.id).run();
      return json({ ok: true });
    }
  }

  // One-time import of client records + TrainHeroic history. The file in public/_imp is
  // AES-GCM encrypted; only this Worker holds the key (IMPORT_KEY secret).
  if (path === '/import-clients' && method === 'POST') {
    if (me.role !== 'coach' || !env.IMPORT_KEY) return err(403, 'Not allowed');
    const res = await env.ASSETS.fetch(new Request(new URL('/_imp/th.bin', url).toString()));
    if (!res.ok) return err(404, 'Nothing to import');
    const buf = new Uint8Array(await res.arrayBuffer());
    const key = await crypto.subtle.importKey('raw', Uint8Array.from(atob(env.IMPORT_KEY), (c) => c.charCodeAt(0)), 'AES-GCM', false, ['decrypt']);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, key, buf.slice(12));
    const text = await new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
    const b = JSON.parse(text);
    const now = Date.now(), ids = {}, stmts = [];
    const put = (col, id, data) => stmts.push(env.DB.prepare('INSERT OR REPLACE INTO docs (scope,col,id,data,updated_at) VALUES (?,?,?,?,?)').bind(scope, col, id, JSON.stringify(data), now));
    for (const [cid, c] of Object.entries(b.clients || {})) {
      if (!validId(cid)) continue;
      const have = await env.DB.prepare("SELECT 1 FROM docs WHERE scope=? AND col='clients' AND id=?").bind(scope, cid).first();
      if (!have) put('clients', cid, { ...c, updatedAt: now });
      if (b.archives && b.archives[cid]) { put('archives', cid, b.archives[cid]); ids[cid] = 'arch-' + cid; }
    }
    const pa = await env.DB.prepare("SELECT data FROM docs WHERE scope=? AND col='private' AND id='archives'").bind(scope).first();
    put('private', 'archives', { ...(pa ? JSON.parse(pa.data) : {}), ...ids });
    await env.DB.batch(stmts);
    return json({ imported: Object.keys(ids) });
  }

  // Bulk upload used once when the coach moves this device's data into the account.
  if (path === '/import' && method === 'POST') {
    if (me.role !== 'coach') return err(403, 'Not allowed');
    const b = await readBody(req);
    const items = Array.isArray(b.items) ? b.items.slice(0, 2000) : [];
    const existing = new Map();
    const r = await env.DB.prepare('SELECT col,id,updated_at FROM docs WHERE scope=?').bind(scope).all();
    for (const d of r.results) existing.set(d.col + '\u0000' + d.id, d.updated_at);
    const stmts = [];
    for (const it of items) {
      if (!it || !COL_RE.test(it.col || '') || !validId(it.id) || !it.data || typeof it.data !== 'object') continue;
      const k = it.col + '\u0000' + it.id;
      const ts = +it.data.updatedAt || 0;
      if (existing.has(k) && existing.get(k) >= ts) continue;
      stmts.push(env.DB.prepare('INSERT OR REPLACE INTO docs (scope,col,id,data,updated_at) VALUES (?,?,?,?,?)')
        .bind(scope, it.col, it.id, JSON.stringify(it.data), ts || Date.now()));
    }
    for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
    return json({ imported: stmts.length });
  }

  return err(404, 'Not found');
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname.startsWith('/api/')) {
      if (!PEPPER_KEY && env.PEPPER) PEPPER_KEY = await crypto.subtle.importKey('raw', enc.encode(env.PEPPER), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      if (!env.PEPPER) return err(503, 'The server is missing its PEPPER secret.');
      try { return await api(req, env, url); }
      catch (e) { console.error(e); return err(500, 'Something went wrong. Try again.'); }
    }
    return env.ASSETS.fetch(req);
  },
};

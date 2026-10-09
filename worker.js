/* Life tools · Cloudflare Worker: serves the pages in /public and the sync API at /api/*
   Lives on the same address as the HTML pages.
   Needs:  a D1 database bound as  DB   and a secret/variable  PIN  (4 digits).
   Tables are created automatically on first use.

   GET  /api/ping                     -> { ok:true }                       (checks the PIN)
   GET  /api/slot/<name>?since=<rev>  -> { rev, same:true } | { rev, at, data }
   PUT  /api/slot/<name>  {base,data} -> { rev, at }  |  409 { rev, at, data }  (someone saved first)
*/
const CHUNK = 500000;            // characters per stored piece (D1 rows max 2 MB)
const MAX_BODY = 12e6;           // largest upload accepted
const IP_TRIES = 5, IP_LOCK = 15 * 60e3;          // 5 wrong PINs from one place -> 15 min pause
const ALL_TRIES = 40, ALL_WIN = 60 * 60e3, ALL_LOCK = 60 * 60e3; // 40 wrong in an hour from anywhere -> 1 h pause

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,PUT,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,X-Pin',
  'Access-Control-Max-Age': '86400'
};
const json = (obj, status = 200) => new Response(JSON.stringify(obj), {
  status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...CORS }
});

let ready = false;
async function setup(db) {
  if (ready) return;
  await db.batch([
    db.prepare('CREATE TABLE IF NOT EXISTS slots (name TEXT PRIMARY KEY, rev INTEGER NOT NULL, wid TEXT NOT NULL, n INTEGER NOT NULL, at INTEGER NOT NULL)'),
    db.prepare('CREATE TABLE IF NOT EXISTS chunks (name TEXT NOT NULL, wid TEXT NOT NULL, i INTEGER NOT NULL, part TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (name, wid, i))'),
    db.prepare('CREATE TABLE IF NOT EXISTS guard (k TEXT PRIMARY KEY, fails INTEGER NOT NULL, since INTEGER NOT NULL, until INTEGER NOT NULL)')
  ]);
  ready = true;
}

function sameText(a, b) {          // compare without leaking timing
  a = String(a); b = String(b);
  let d = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return d === 0;
}
async function getGuard(db, k) { return (await db.prepare('SELECT fails, since, until FROM guard WHERE k=?').bind(k).first()) || { fails: 0, since: 0, until: 0 }; }
async function putGuard(db, k, g) { await db.prepare('INSERT INTO guard (k,fails,since,until) VALUES (?,?,?,?) ON CONFLICT(k) DO UPDATE SET fails=excluded.fails, since=excluded.since, until=excluded.until').bind(k, g.fails, g.since, g.until).run(); }

async function checkPin(request, env) {
  const db = env.DB, now = Date.now();
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
  const kIp = 'ip:' + ip.slice(0, 64);
  const [gIp, gAll] = await Promise.all([getGuard(db, kIp), getGuard(db, 'all')]);
  const until = Math.max(gIp.until, gAll.until);
  if (until > now) return json({ error: 'locked', retryIn: Math.ceil((until - now) / 1000) }, 429);
  const pin = request.headers.get('X-Pin') || '';
  if (sameText(pin, String(env.PIN).trim())) {
    if (gIp.fails) await putGuard(db, kIp, { fails: 0, since: now, until: 0 });
    return null;
  }
  // wrong PIN
  gIp.fails++; if (gIp.fails >= IP_TRIES) { gIp.until = now + IP_LOCK; gIp.fails = 0; }
  if (now - gAll.since > ALL_WIN) { gAll.fails = 0; gAll.since = now; }
  gAll.fails++; if (gAll.fails >= ALL_TRIES) { gAll.until = now + ALL_LOCK; gAll.fails = 0; gAll.since = now; }
  await Promise.all([putGuard(db, kIp, gIp), putGuard(db, 'all', gAll)]);
  if (gIp.until > now) return json({ error: 'locked', retryIn: Math.ceil(IP_LOCK / 1000) }, 429);
  return json({ error: 'pin', triesLeft: IP_TRIES - gIp.fails }, 401);
}

async function readSlot(db, name) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const s = await db.prepare('SELECT rev, wid, n, at FROM slots WHERE name=?').bind(name).first();
    if (!s) return { rev: 0, at: 0, data: null };
    const { results } = await db.prepare('SELECT part FROM chunks WHERE name=? AND wid=? ORDER BY i').bind(name, s.wid).all();
    if (results.length === s.n) return { rev: s.rev, at: s.at, data: results.map(r => r.part).join('') };
    // a save finished between our two reads; try again
  }
  throw new Error('busy');
}

async function writeSlot(db, name, base, data) {
  const now = Date.now(), wid = crypto.randomUUID(), parts = [];
  for (let i = 0; i < data.length; i += CHUNK) parts.push(data.slice(i, i + CHUNK));
  if (!parts.length) parts.push('');
  const ins = db.prepare('INSERT INTO chunks (name, wid, i, part, at) VALUES (?,?,?,?,?)');
  for (let i = 0; i < parts.length; i += 20) await db.batch(parts.slice(i, i + 20).map((p, j) => ins.bind(name, wid, i + j, p, now)));
  const rev = base + 1;
  const r = base === 0
    ? await db.prepare('INSERT INTO slots (name, rev, wid, n, at) VALUES (?,?,?,?,?) ON CONFLICT(name) DO NOTHING').bind(name, rev, wid, parts.length, now).run()
    : await db.prepare('UPDATE slots SET rev=?, wid=?, n=?, at=? WHERE name=? AND rev=?').bind(rev, wid, parts.length, now, name, base).run();
  if (!r.meta || r.meta.changes !== 1) {               // someone else saved first
    await db.prepare('DELETE FROM chunks WHERE name=? AND wid=?').bind(name, wid).run();
    return null;
  }
  // tidy old pieces (older than a minute, so a save that is mid-way is never touched)
  await db.prepare('DELETE FROM chunks WHERE name=? AND wid<>? AND at<?').bind(name, wid, now - 60e3).run();
  return { rev, at: now };
}

async function onRequest(ctx) {
  const spare = ctx.request.method === 'PUT' ? ctx.request.clone() : ctx.request;
  const r = await handle(ctx);
  if (r.status === 500) {                    // tables missing (new or emptied database): create them and retry once
    const body = await r.clone().text();
    if (/no such table/i.test(body)) { ready = false; return handle({ ...ctx, request: spare }); }
  }
  return r;
}
async function handle({ request, env, params }) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  try {
    if (!env.DB) return json({ error: 'setup', detail: 'No D1 database is linked as DB.' }, 500);
    if (!env.PIN || !/^\d{4,8}$/.test(String(env.PIN).trim())) return json({ error: 'setup', detail: 'PIN is not set (4 digits).' }, 500);
    await setup(env.DB);
    const denied = await checkPin(request, env);
    if (denied) return denied;

    const path = Array.isArray(params.path) ? params.path : String(params.path || '').split('/').filter(Boolean);
    if (path[0] === 'ping' && path.length === 1 && request.method === 'GET') return json({ ok: true, time: Date.now() });

    if (path[0] === 'slot' && path.length === 2) {
      const name = path[1];
      if (!/^[a-z0-9-]{1,40}$/.test(name)) return json({ error: 'name' }, 400);
      if (request.method === 'GET') {
        const since = Number(new URL(request.url).searchParams.get('since'));
        if (Number.isInteger(since) && since > 0) {
          const s = await env.DB.prepare('SELECT rev FROM slots WHERE name=?').bind(name).first();
          if (s && s.rev === since) return json({ rev: since, same: true });
        }
        return json(await readSlot(env.DB, name));
      }
      if (request.method === 'PUT') {
        const len = Number(request.headers.get('Content-Length') || 0);
        if (len > MAX_BODY) return json({ error: 'size' }, 413);
        const text = await request.text();
        if (text.length > MAX_BODY) return json({ error: 'size' }, 413);
        let body; try { body = JSON.parse(text); } catch (e) { return json({ error: 'json' }, 400); }
        const base = Number(body && body.base);
        if (!Number.isInteger(base) || base < 0 || typeof body.data !== 'string') return json({ error: 'body' }, 400);
        const ok = await writeSlot(env.DB, name, base, body.data);
        if (ok) return json(ok);
        return json(await readSlot(env.DB, name), 409);
      }
    }
    return json({ error: 'not found' }, 404);
  } catch (e) {
    return json({ error: 'server', detail: String(e && e.message || e).slice(0, 200) }, 500);
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      const path = url.pathname.slice(5).split('/').filter(Boolean);
      return onRequest({ request, env, params: { path } });
    }
    if (url.pathname === '/' || url.pathname === '/index.html') return Response.redirect(url.origin + '/the-way.html', 302);
    return env.ASSETS.fetch(request);
  }
};

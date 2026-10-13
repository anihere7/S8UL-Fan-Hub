// Cloudflare Pages Function: shared storage for the Fan wall, Match Center and card Leaderboard.
// Routes: GET/POST/DELETE /api/wall, /api/matches, /api/leaderboard and /api/members
// Needs: a KV namespace bound as DATA, and an ADMIN_KEY secret (for moderation).

const LIMITS = { wall: { max: 500 }, matches: { max: 300 }, leaderboard: { max: 1000 }, members: { max: 5000 } };
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{1,18}[A-Za-z0-9]$/; // 3 to 20 characters
const RESERVED = ['admin', 'administrator', 'moderator', 'owner', 's8ul', 'support'];
const LAUNCH = Date.UTC(2026, 9, 10); // the card game started on 10 Oct 2026 (one card per day at most)

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });

const clean = (v, n) =>
  String(v == null ? '' : v)
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, n);

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, '0')).join('');
}

export async function onRequest({ request, env, params }) {
  const kind = params.kind;
  if (!LIMITS[kind]) return json({ error: 'not found' }, 404);
  if (!env.DATA) return json({ error: 'storage not configured' }, 503);

  const key = 'list:' + kind;
  const isAdmin = !!env.ADMIN_KEY && request.headers.get('x-admin-key') === env.ADMIN_KEY;
  const read = async () => {
    try { return JSON.parse((await env.DATA.get(key)) || '[]') || []; } catch (e) { return []; }
  };
  const write = (items) => env.DATA.put(key, JSON.stringify(items.slice(0, LIMITS[kind].max)));
  const ipLimit = async () => {
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const rk = 'rl:' + kind + ':' + ip;
    if (await env.DATA.get(rk)) return true;
    await env.DATA.put(rk, '1', { expirationTtl: 60 });
    return false;
  };

  if (request.method === 'GET') {
    const items = await read();
    if (kind === 'members') {
      // Only the admin can see who has an account. PIN hashes are never sent.
      if (!isAdmin) return json({ error: 'forbidden' }, 403);
      return json({
        items: items
          .slice()
          .sort((a, b) => (b.last || 0) - (a.last || 0))
          .map((x) => ({ id: x.id, n: x.n, created: x.created, last: x.last, count: x.count || 0 })),
      });
    }
    if (kind === 'leaderboard') {
      const top = items
        .slice()
        .sort((a, b) => b.c - a.c || b.t - a.t || a.u - b.u)
        .slice(0, 50)
        .map((x) => (isAdmin ? { id: x.id, n: x.n, c: x.c, t: x.t } : { n: x.n, c: x.c, t: x.t }));
      return json({ items: top });
    }
    return json({ items });
  }

  if (request.method === 'POST') {
    let b;
    try { b = await request.json(); } catch (e) { return json({ error: 'bad request' }, 400); }
    if (b && b.website) return json({ ok: true }); // honeypot: bots fill this hidden field

    if (kind === 'members') {
      // Username + 4-digit PIN accounts. Wrong PINs lock the account for 15 minutes after 5 tries.
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const ck = 'mrl:' + ip;
      const tries = parseInt((await env.DATA.get(ck)) || '0', 10);
      if (tries >= 15) return json({ error: 'too many requests' }, 429);
      await env.DATA.put(ck, String(tries + 1), { expirationTtl: 60 });

      const n = clean(b.n, 20);
      const pin = String(b.pin == null ? '' : b.pin);
      if (!/^\d{4}$/.test(pin)) return json({ error: 'invalid pin' }, 400);
      if (!NAME_RE.test(n)) return json({ error: 'invalid name' }, 400);
      const nk = n.toLowerCase();
      const items = await read();
      const m = items.find((x) => x.nk === nk);

      if (b.action === 'register') {
        if (m || RESERVED.includes(nk)) return json({ error: 'name taken' }, 409);
        const salt = crypto.randomUUID();
        const now = Date.now();
        items.unshift({
          id: crypto.randomUUID(), n, nk, salt, ph: await sha256(salt + ':' + pin),
          created: now, last: now, count: 1, fails: 0, lock: 0,
        });
        await write(items);
        return json({ ok: true, n });
      }
      if (b.action === 'login') {
        if (!m) return json({ error: 'wrong' }, 401);
        if ((m.lock || 0) > Date.now()) return json({ error: 'locked' }, 423);
        if ((await sha256(m.salt + ':' + pin)) !== m.ph) {
          m.fails = (m.fails || 0) + 1;
          if (m.fails >= 5) { m.lock = Date.now() + 15 * 60 * 1000; m.fails = 0; }
          await write(items);
          return json({ error: 'wrong' }, 401);
        }
        m.fails = 0; m.lock = 0; m.last = Date.now(); m.count = (m.count || 0) + 1;
        await write(items);
        return json({ ok: true, n: m.n });
      }
      return json({ error: 'bad request' }, 400);
    }

    if (kind === 'leaderboard') {
      const tok = clean(b.tok, 64);
      const n = clean(b.n, 20);
      const c = Math.floor(Number(b.c));
      const t = Math.floor(Number(b.t));
      if (tok.length < 16 || n.length < 2) return json({ error: 'missing fields' }, 400);
      // A fan can win at most one card a day, so totals are capped by the days since launch.
      const maxT = Math.floor((Date.now() - LAUNCH) / 864e5) + 2;
      if (![c, t].every(Number.isFinite) || c < 0 || t < c || c > 100 || t > maxT) {
        return json({ error: 'invalid numbers' }, 400);
      }
      const k = await sha256(tok);
      const items = await read();
      const mine = items.find((x) => x.k === k);
      if (items.some((x) => x.k !== k && x.n.toLowerCase() === n.toLowerCase())) {
        return json({ error: 'name taken' }, 409);
      }
      if (mine) {
        mine.n = n;
        mine.c = Math.max(mine.c, c);
        mine.t = Math.max(mine.t, t);
        mine.u = Date.now();
      } else {
        if (!isAdmin && (await ipLimit())) return json({ error: 'too many requests' }, 429);
        items.unshift({ id: crypto.randomUUID(), k, n, c, t, u: Date.now() });
      }
      await write(items);
      return json({ ok: true });
    }

    if (!isAdmin && (await ipLimit())) return json({ error: 'too many requests' }, 429);

    const item = { id: crypto.randomUUID(), t: Date.now() };
    if (kind === 'wall') {
      item.n = clean(b.n, 30);
      item.m = clean(b.m, 240);
      if (!item.n || !item.m) return json({ error: 'missing fields' }, 400);
    } else {
      item.game = clean(b.game, 40);
      item.event = clean(b.event, 90);
      item.who = clean(b.who, 60);
      item.loc = clean(b.loc, 80);
      item.note = clean(b.note, 200);
      item.status = ['upcoming', 'live', 'done'].includes(b.status) ? b.status : 'upcoming';
      item.ts = Number(b.ts);
      if (!isFinite(item.ts) || item.ts < 0 || item.ts > 4102444800000) item.ts = Date.now();
      item.fan = !isAdmin;
      if (!item.game || !item.event) return json({ error: 'missing fields' }, 400);
    }
    const items = await read();
    items.unshift(item);
    await write(items);
    return json({ ok: true, id: item.id });
  }

  if (request.method === 'DELETE') {
    if (!isAdmin) return json({ error: 'forbidden' }, 403);
    const id = new URL(request.url).searchParams.get('id');
    await write((await read()).filter((x) => x.id !== id));
    return json({ ok: true });
  }

  return json({ error: 'method not allowed' }, 405);
}

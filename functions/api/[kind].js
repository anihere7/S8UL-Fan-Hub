// Cloudflare Pages Function: shared storage for the Fan wall, Match Center and card Leaderboard.
// Routes: GET/POST/DELETE /api/wall, /api/matches and /api/leaderboard
// Needs: a KV namespace bound as DATA, and an ADMIN_KEY secret (for moderation).

const LIMITS = { wall: { max: 500 }, matches: { max: 300 }, leaderboard: { max: 1000 } };
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

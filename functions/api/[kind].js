// Cloudflare Pages Function: shared storage for the Fan wall and Match Center.
// Routes: GET/POST/DELETE /api/wall and /api/matches
// Needs: a KV namespace bound as DATA, and an ADMIN_KEY secret (for moderation).

const LIMITS = { wall: { max: 500 }, matches: { max: 300 } };

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

export async function onRequest({ request, env, params }) {
  const kind = params.kind;
  if (!LIMITS[kind]) return json({ error: 'not found' }, 404);
  if (!env.DATA) return json({ error: 'storage not configured' }, 503);

  const key = 'list:' + kind;
  const isAdmin = !!env.ADMIN_KEY && request.headers.get('x-admin-key') === env.ADMIN_KEY;
  const read = async () => {
    try { return JSON.parse((await env.DATA.get(key)) || '[]') || []; } catch (e) { return []; }
  };

  if (request.method === 'GET') {
    return json({ items: await read() });
  }

  if (request.method === 'POST') {
    let b;
    try { b = await request.json(); } catch (e) { return json({ error: 'bad request' }, 400); }
    if (b && b.website) return json({ ok: true }); // honeypot: bots fill this hidden field

    if (!isAdmin) {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const rk = 'rl:' + kind + ':' + ip;
      if (await env.DATA.get(rk)) return json({ error: 'too many requests' }, 429);
      await env.DATA.put(rk, '1', { expirationTtl: 60 });
    }

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
    await env.DATA.put(key, JSON.stringify(items.slice(0, LIMITS[kind].max)));
    return json({ ok: true, id: item.id });
  }

  if (request.method === 'DELETE') {
    if (!isAdmin) return json({ error: 'forbidden' }, 403);
    const id = new URL(request.url).searchParams.get('id');
    const items = (await read()).filter((x) => x.id !== id);
    await env.DATA.put(key, JSON.stringify(items));
    return json({ ok: true });
  }

  return json({ error: 'method not allowed' }, 405);
}

/**
 * INES tracking API — Cloudflare Pages Function
 *
 * Required Cloudflare Pages settings (Settings → Variables and Secrets / Bindings):
 *   KV binding       INES_KV          (a KV namespace that stores tracking data and users)
 *   Secret           ADMIN_USERNAME   owner login name (lowercase Latin letters/digits)
 *   Secret           ADMIN_PASSWORD   owner password (at least 10 characters)
 *   Secret           SESSION_SECRET   long random string used to sign login sessions
 *
 * Routes (all under /api):
 *   GET    tracking          public: all tracking records
 *   GET    downloads         public: download counts per document
 *   POST   count/:lang       public: record one download (ar | en)
 *   GET    actions          public: approved executive actions (all of them when signed in)
 *   PUT    actions          signed-in: create or update one action
 *   POST   actions/import   signed-in: bulk import actions as drafts
 *   DELETE actions/:id      admin: remove one action
 *   PUT    tracking          signed-in: update one record
 *   POST   login             sign in (sets an HttpOnly cookie)
 *   POST   logout            sign out
 *   GET    me                current session
 *   GET    users             admin: list users
 *   POST   users             admin: add user
 *   DELETE users/:username   admin: remove user
 */

const COOKIE = "ines_session";
const SESSION_HOURS = 8;
const PBKDF2_ITER = 100000;               // Cloudflare Workers maximum
const ID_RE = /^(ge|tv|he|fn)-(k|p)\d{1,2}$/;
const USER_RE = /^[a-z0-9._-]{3,32}$/;
const STATUSES = ["not_started", "on_track", "at_risk", "off_track", "achieved"];
const ACT_STATUSES = ["not_started", "ongoing", "delayed", "stopped", "done"];
const WORKFLOW = ["draft", "review", "approved"];
const ACT_MAX = 2500;                     // ceiling on stored actions
const ACT_KEY = "actions";
const enc = new TextEncoder();

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers } });
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64u = str => Uint8Array.from(atob(str.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((str.length + 3) % 4)), c => c.charCodeAt(0));
const clip = (v, n) => String(v ?? "").trim().slice(0, n);

async function hmacKey(secret){
  return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
async function hashPassword(password, saltB64){
  const salt = saltB64 ? fromB64u(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: PBKDF2_ITER, hash: "SHA-256" }, key, 256);
  return { salt: b64u(salt), hash: b64u(bits) };
}
function safeEqual(a, b){
  if(typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let r = 0; for(let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0;
}
async function signSession(env, payload){
  const body = b64u(enc.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(env.SESSION_SECRET), enc.encode(body));
  return body + "." + b64u(sig);
}
async function readSession(request, env){
  const cookie = request.headers.get("Cookie") || "";
  const m = cookie.match(new RegExp("(?:^|;\\s*)" + COOKIE + "=([^;]+)"));
  if(!m) return null;
  const [body, sig] = m[1].split(".");
  if(!body || !sig) return null;
  try{
    const ok = await crypto.subtle.verify("HMAC", await hmacKey(env.SESSION_SECRET), fromB64u(sig), enc.encode(body));
    if(!ok) return null;
    const s = JSON.parse(new TextDecoder().decode(fromB64u(body)));
    if(!s.exp || s.exp < Date.now()) return null;
    if(!s.owner){ // make sure a removed user cannot keep using an old session
      const u = await env.INES_KV.get("user:" + s.user, "json");
      if(!u) return null;
      s.role = u.role; s.name = u.name;
    }
    return s;
  }catch(e){ return null; }
}
const cookieHeader = (value, maxAge) => `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;

async function rebuildAggregate(env){
  const records = {};
  let cursor;
  do{
    const page = await env.INES_KV.list({ prefix: "rec:", cursor });
    const values = await Promise.all(page.keys.map(k => env.INES_KV.get(k.name, "json")));
    page.keys.forEach((k, i) => { if(values[i]) records[k.name.slice(4)] = values[i]; });
    cursor = page.list_complete ? null : page.cursor;
  }while(cursor);
  const agg = { exportedAt: new Date().toISOString(), records };
  await env.INES_KV.put("tracking", JSON.stringify(agg));
  return agg;
}


/* ---- executive actions (one KV key holds them all: cheap on the free plan) ---- */
const numOrNull = v => { if(v === null || v === undefined || v === "") return null; const n = Number(v); return Number.isFinite(n) ? n : null; };
const pick = (v, list, dflt) => list.includes(v) ? v : dflt;

async function readActions(env){
  const a = await env.INES_KV.get(ACT_KEY, "json");
  return (a && typeof a === "object" && a.items) ? a : { exportedAt: "", items: {} };
}
function publicActions(store){
  const items = {};
  for(const [id, a] of Object.entries(store.items)) if(a.workflow === "approved") items[id] = a;
  return { exportedAt: store.exportedAt, items };
}
function cleanAction(b, prev, session, now){
  const periods = (Array.isArray(b.periods) ? b.periods : (prev && prev.periods) || []).slice(-24).map(p => ({
    p: clip(p.p, 24), target: numOrNull(p.target), achieved: numOrNull(p.achieved),
    done: clip(p.done, 700), reason: clip(p.reason, 500), next: clip(p.next, 500),
    at: clip(p.at, 40) || now, by: clip(p.by, 80) || session.name
  }));
  return {
    id: (prev && prev.id) || clip(b.id, 40),
    ref: clip(b.ref, 60), ministry: clip(b.ministry, 60), sector: pick(clip(b.sector, 4), ["ge","tv","he"], "ge"),
    component: clip(b.component, 160), objective: clip(b.objective, 300), program: clip(b.program, 300), subprogram: clip(b.subprogram, 300),
    title: clip(b.title, 500), indicator: clip(b.indicator, 400), kpi: clip(b.kpi, 20),
    unit: clip(b.unit, 40), targetTotal: numOrNull(b.targetTotal), achievedTotal: numOrNull(b.achievedTotal),
    start: clip(b.start, 20), end: clip(b.end, 20),
    implementer: clip(b.implementer, 200), beneficiary: clip(b.beneficiary, 200),
    status: pick(clip(b.status, 20), ACT_STATUSES, "not_started"),
    workflow: pick(clip(b.workflow, 20), WORKFLOW, "draft"),
    cost: numOrNull(b.cost), funding: numOrNull(b.funding), spent: numOrNull(b.spent),
    currency: clip(b.currency, 10) || "IQD", amountUnit: pick(clip(b.amountUnit, 12), ["one","thousand","million","billion"], "one"),
    fundingSource: clip(b.fundingSource, 200), evidence: clip(b.evidence, 400).slice(0, 400), note: clip(b.note, 1500),
    periods,
    createdAt: (prev && prev.createdAt) || now, createdBy: (prev && prev.createdBy) || session.name,
    by: session.name, user: session.user, updatedAt: now
  };
}
function newId(){ return "a" + Date.now().toString(36) + Math.random().toString(36).slice(2, 6); }

export async function onRequest(context){
  const { request, env, params } = context;
  const path = Array.isArray(params.path) ? params.path : (params.path ? [params.path] : []);
  const route = path.join("/");
  const method = request.method.toUpperCase();

  if(!env.INES_KV || !env.SESSION_SECRET || !env.ADMIN_USERNAME || !env.ADMIN_PASSWORD){
    if(route === "tracking" && method === "GET") return json({ error: "not_configured" }, 503);
    return json({ error: "not_configured" }, 503);
  }
  // simple CSRF guard for state-changing requests (cookie is also SameSite=Strict)
  if(method !== "GET" && request.headers.get("X-Requested-With") !== "ines") return json({ error: "bad_request" }, 400);

  try{
    /* ---- public data ---- */
    if(route === "tracking" && method === "GET"){
      const agg = await env.INES_KV.get("tracking", "json");
      return json(agg || { exportedAt: "", records: {} }, 200, { "Cache-Control": "public, max-age=30" });
    }

    /* ---- executive actions: public read ---- */
    if(route === "actions" && method === "GET"){
      const store = await readActions(env);
      const s0 = await readSession(request, env);
      return s0 ? json(store) : json(publicActions(store), 200, { "Cache-Control": "public, max-age=30" });
    }

    /* ---- download counters ---- */
    if(route === "downloads" && method === "GET"){
      const [ar, en] = await Promise.all([env.INES_KV.get("dl:ar"), env.INES_KV.get("dl:en")]);
      return json({ counts: { ar: Number(ar) || 0, en: Number(en) || 0 } }, 200, { "Cache-Control": "public, max-age=60" });
    }
    if(path[0] === "count" && path[1] && method === "POST"){
      const l = path[1] === "en" ? "en" : path[1] === "ar" ? "ar" : null;
      if(!l) return json({ error: "bad_request" }, 400);
      const n = (Number(await env.INES_KV.get("dl:" + l)) || 0) + 1;
      await env.INES_KV.put("dl:" + l, String(n));
      return json({ count: n });
    }

    /* ---- auth ---- */
    if(route === "login" && method === "POST"){
      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const failKey = "fail:" + ip;
      const fails = Number(await env.INES_KV.get(failKey)) || 0;
      if(fails >= 5) return json({ error: "locked" }, 429);
      const body = await request.json().catch(() => ({}));
      const username = clip(body.username, 32).toLowerCase(); const password = String(body.password || "");
      let session = null;
      if(safeEqual(username, String(env.ADMIN_USERNAME).toLowerCase()) && safeEqual(password, String(env.ADMIN_PASSWORD))){
        session = { user: username, name: env.ADMIN_NAME || username, role: "admin", owner: true };
      }else if(USER_RE.test(username)){
        const u = await env.INES_KV.get("user:" + username, "json");
        if(u){ const h = await hashPassword(password, u.salt); if(safeEqual(h.hash, u.hash)) session = { user: username, name: u.name, role: u.role, owner: false }; }
      }
      if(!session){
        await env.INES_KV.put(failKey, String(fails + 1), { expirationTtl: 900 });
        return json({ error: "unauthorized" }, 401);
      }
      const token = await signSession(env, { ...session, exp: Date.now() + SESSION_HOURS * 3600e3 });
      return json(session, 200, { "Set-Cookie": cookieHeader(token, SESSION_HOURS * 3600) });
    }
    if(route === "logout" && method === "POST") return json({ ok: true }, 200, { "Set-Cookie": cookieHeader("", 0) });

    const session = await readSession(request, env);
    if(route === "me" && method === "GET"){
      return session ? json({ user: session.user, name: session.name, role: session.role, owner: !!session.owner }) : json({ error: "unauthorized" }, 401);
    }
    if(!session) return json({ error: "unauthorized" }, 401);

    /* ---- update one tracking record ---- */
    if(route === "tracking" && method === "PUT"){
      const b = await request.json().catch(() => ({}));
      if(!ID_RE.test(String(b.id || ""))) return json({ error: "bad_id" }, 400);
      const status = STATUSES.includes(b.status) ? b.status : "not_started";
      let progress = null;
      if(b.progress !== null && b.progress !== "" && b.progress !== undefined){
        progress = Number(b.progress);
        if(!Number.isFinite(progress) || progress < 0 || progress > 100) return json({ error: "bad_progress" }, 400);
        progress = Math.round(progress);
      }
      const now = new Date().toISOString();
      const prev = await env.INES_KV.get("rec:" + b.id, "json") || {};
      const entry = { status, progress, value: clip(b.value, 120), by: session.name, user: session.user, at: now };
      const record = {
        kind: b.id.includes("-p") ? "prog" : "kpi", status, progress,
        value: clip(b.value, 120), year: clip(b.year, 40), note: clip(b.note, 1200),
        by: session.name, user: session.user, updatedAt: now,
        history: [...(Array.isArray(prev.history) ? prev.history : []), entry].slice(-15)
      };
      await env.INES_KV.put("rec:" + b.id, JSON.stringify(record));
      const agg = await rebuildAggregate(env);
      return json({ record, exportedAt: agg.exportedAt });
    }

    /* ---- executive actions: write ---- */
    if(route === "actions" && method === "PUT"){
      const b = await request.json().catch(() => ({}));
      if(!clip(b.title, 500)) return json({ error: "bad_title" }, 400);
      const store = await readActions(env);
      const id = clip(b.id, 40) && store.items[clip(b.id, 40)] ? clip(b.id, 40) : newId();
      if(!store.items[id] && Object.keys(store.items).length >= ACT_MAX) return json({ error: "full" }, 409);
      const now = new Date().toISOString();
      const rec = cleanAction({ ...b, id }, store.items[id] || null, session, now);
      rec.id = id;
      store.items[id] = rec; store.exportedAt = now;
      await env.INES_KV.put(ACT_KEY, JSON.stringify(store));
      return json({ action: rec, exportedAt: store.exportedAt });
    }
    if(route === "actions/import" && method === "POST"){
      const b = await request.json().catch(() => ({}));
      const items = Array.isArray(b.items) ? b.items : null;
      if(!items || !items.length) return json({ error: "bad_request" }, 400);
      const store = await readActions(env);
      if(b.replace === true) store.items = {};
      const now = new Date().toISOString();
      let added = 0, skipped = 0;
      for(const raw of items){
        if(Object.keys(store.items).length >= ACT_MAX){ skipped++; continue; }
        if(!clip(raw.title, 500)){ skipped++; continue; }
        const id = newId();
        const rec = cleanAction({ ...raw, id, workflow: "draft" }, null, session, now);
        rec.id = id; store.items[id] = rec; added++;
      }
      store.exportedAt = now;
      await env.INES_KV.put(ACT_KEY, JSON.stringify(store));
      return json({ added, skipped, total: Object.keys(store.items).length, exportedAt: now });
    }
    if(path[0] === "actions" && path[1] && method === "DELETE"){
      if(session.role !== "admin" && !session.owner) return json({ error: "forbidden" }, 403);
      const store = await readActions(env);
      delete store.items[decodeURIComponent(path[1])];
      store.exportedAt = new Date().toISOString();
      await env.INES_KV.put(ACT_KEY, JSON.stringify(store));
      return json({ ok: true, total: Object.keys(store.items).length });
    }

    /* ---- users (admin only) ---- */
    if(route.startsWith("users")){
      if(session.role !== "admin" && !session.owner) return json({ error: "forbidden" }, 403);
      if(route === "users" && method === "GET"){
        const users = [{ username: String(env.ADMIN_USERNAME).toLowerCase(), name: env.ADMIN_NAME || env.ADMIN_USERNAME, role: "admin", owner: true }];
        let cursor;
        do{
          const page = await env.INES_KV.list({ prefix: "user:", cursor });
          const vals = await Promise.all(page.keys.map(k => env.INES_KV.get(k.name, "json")));
          vals.forEach(v => { if(v) users.push({ username: v.username, name: v.name, role: v.role, owner: false }); });
          cursor = page.list_complete ? null : page.cursor;
        }while(cursor);
        return json({ users });
      }
      if(route === "users" && method === "POST"){
        const b = await request.json().catch(() => ({}));
        const username = clip(b.username, 32).toLowerCase();
        if(!USER_RE.test(username) || username === String(env.ADMIN_USERNAME).toLowerCase()) return json({ error: "bad_username" }, 400);
        if(String(b.password || "").length < 10) return json({ error: "bad_password" }, 400);
        if(await env.INES_KV.get("user:" + username)) return json({ error: "exists" }, 409);
        const h = await hashPassword(String(b.password));
        const user = { username, name: clip(b.name, 80) || username, role: b.role === "admin" ? "admin" : "editor", salt: h.salt, hash: h.hash, createdAt: new Date().toISOString(), createdBy: session.user };
        await env.INES_KV.put("user:" + username, JSON.stringify(user));
        return json({ ok: true });
      }
      if(path[0] === "users" && path[1] && method === "DELETE"){
        const username = decodeURIComponent(path[1]).toLowerCase();
        if(username === session.user) return json({ error: "forbidden" }, 403);
        await env.INES_KV.delete("user:" + username);
        return json({ ok: true });
      }
    }
    return json({ error: "not_found" }, 404);
  }catch(err){
    return json({ error: "server_error" }, 500);
  }
}

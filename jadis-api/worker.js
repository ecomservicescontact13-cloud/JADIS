// ═══════════════════════════════════════════════════════════════
//  JADIS — Cloudflare Worker (backend complet gratuit)
//
//  SETUP (une seule fois, 5 minutes) :
//  1. Va sur https://dash.cloudflare.com → Workers & Pages
//  2. Create Worker → colle ce fichier → Deploy
//  3. Workers & Pages → KV → Create namespace → nom : "JADIS_DATA"
//  4. Ton Worker → Settings → Variables → KV Namespace Bindings
//     Binding name : JADIS_DATA  → sélectionne le namespace créé
//  5. Settings → Variables → Environment Variables (encrypted)
//     JWT_SECRET → n'importe quelle longue chaîne secrète
//     ex : "jadis2026xSecretClef!Immuable$Forte"
//  6. Copie l'URL du Worker (ex: jadis-api.ton-compte.workers.dev)
//     et colle-la dans api-config.js → JADIS_API_URL
// ═══════════════════════════════════════════════════════════════

const ADMIN_EMAILS = ['issamboussalah131@gmail.com', 'shanedarren42@gmail.com'];

const ALLOWED_ORIGINS = [
  'https://jadis.pages.dev',
  'http://localhost',        // développement local
  'http://127.0.0.1'
];

function getCORS(request) {
  const origin = request.headers.get('Origin') || '';
  const allowed = ALLOWED_ORIGINS.some(o => origin.startsWith(o)) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Credentials': 'true',
    'Content-Type': 'application/json'
  };
}

// ── Réponses helpers ─────────────────────────────────────────
let _req = null; // référence à la request courante pour CORS

function ok(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: getCORS(_req || { headers: { get: () => '' } }) });
}
function fail(msg, status = 400) {
  return new Response(JSON.stringify({ error: msg }), { status, headers: getCORS(_req || { headers: { get: () => '' } }) });
}

// ── JWT (Web Crypto, sans dépendance) ────────────────────────
function b64u(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function ab64u(ab) {
  return btoa(String.fromCharCode(...new Uint8Array(ab)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function db64u(str) {
  return Uint8Array.from(atob(str.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}

async function signJWT(payload, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const h = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const b = b64u(JSON.stringify({ ...payload, iat: Math.floor(Date.now() / 1000) }));
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${h}.${b}`));
  return `${h}.${b}.${ab64u(sig)}`;
}

async function verifyJWT(token, secret) {
  const parts = (token || '').split('.');
  if (parts.length !== 3) throw new Error('token invalide');
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
  );
  const valid = await crypto.subtle.verify('HMAC', key, db64u(parts[2]), enc.encode(`${parts[0]}.${parts[1]}`));
  if (!valid) throw new Error('signature invalide');
  const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
  if (payload.exp && payload.exp < Date.now() / 1000) throw new Error('token expiré');
  return payload;
}

// ── Hachage de mot de passe (PBKDF2 via Web Crypto) ──────────
async function hashPwd(pwd, saltB64 = null) {
  const enc = new TextEncoder();
  const salt = saltB64 ? db64u(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(pwd), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' }, key, 256
  );
  return `${ab64u(salt)}:${ab64u(bits)}`;
}

async function verifyPwd(pwd, stored) {
  const [salt] = stored.split(':');
  return (await hashPwd(pwd, salt)) === stored;
}

// ── Auth du token entrant ────────────────────────────────────
async function getSession(request, env) {
  const auth = (request.headers.get('Authorization') || '').replace('Bearer ', '');
  if (!auth) return null;
  try { return await verifyJWT(auth, env.JWT_SECRET); }
  catch { return null; }
}

// ── Tracking interne ─────────────────────────────────────────
async function logEvent(env, email, type, extra = {}) {
  try {
    const events = (await env.JADIS_DATA.get('events', 'json')) || [];
    events.push({ email, type, timestamp: new Date().toISOString(), ...extra });
    if (events.length > 2000) events.splice(0, events.length - 2000);
    await env.JADIS_DATA.put('events', JSON.stringify(events));
  } catch (_) {}
}

// ════════════════════════════════════════════════════════════════
//  ROUTES
// ════════════════════════════════════════════════════════════════
export default {
  async fetch(request, env) {
    _req = request;
    if (request.method === 'OPTIONS') return new Response('', { headers: getCORS(request) });

    const path = new URL(request.url).pathname.replace(/^\/+/, '');
    const m = request.method;

    try {
      if (path === 'auth/login'    && m === 'POST')   return login(request, env);
      if (path === 'auth/register' && m === 'POST')   return register(request, env);
      if (path === 'auth/verify'   && m === 'POST')   return verify(request, env);
      if (path === 'user/save'     && m === 'POST')   return userSave(request, env);
      if (path === 'user/data'     && m === 'GET')    return userData(request, env);
      if (path === 'admin/users'   && m === 'GET')    return adminUsers(request, env);
      if (path === 'admin/stats'   && m === 'GET')    return adminStats(request, env);
      if (path === 'admin/events'  && m === 'GET')    return adminEvents(request, env);
      if (path === 'admin/grant'   && m === 'POST')   return adminGrant(request, env);
      if (path === 'admin/revoke'  && m === 'POST')   return adminRevoke(request, env);
      if (path === 'track'         && m === 'POST')   return track(request, env);
      return fail('Route introuvable', 404);
    } catch (e) {
      return fail(e.message || 'Erreur serveur', 500);
    }
  }
};

// ── LOGIN ────────────────────────────────────────────────────
async function login(request, env) {
  const { email, password, name } = await request.json();
  if (!email) return fail('Email requis');
  const em = email.toLowerCase().trim();
  const isAdmin = ADMIN_EMAILS.includes(em);

  if (isAdmin) {
    // Admins : pas de mot de passe requis pour l'instant
    const displayName = name || em.split('@')[0];
    const token = await signJWT(
      { userId: em, email: em, name: displayName, isAdmin: true, isSubscriber: true,
        exp: Math.floor(Date.now() / 1000) + 86400 * 30 },
      env.JWT_SECRET
    );
    await logEvent(env, em, 'login', { name: displayName, isAdmin: true });
    return ok({ token, isAdmin: true, isSubscriber: true, name: displayName });
  }

  if (!password) return fail('Mot de passe requis');

  const user = await env.JADIS_DATA.get(`user:${em}`, 'json');
  if (!user) return fail('Aucun compte avec cet email', 401);

  const valid = await verifyPwd(password, user.passwordHash);
  if (!valid) return fail('Mot de passe incorrect', 401);

  // Mise à jour lastLogin
  await env.JADIS_DATA.put(`user:${em}`, JSON.stringify({ ...user, lastLogin: new Date().toISOString() }));

  const isSubscriber = !!(await env.JADIS_DATA.get(`subscriber:${em}`));
  const token = await signJWT(
    { userId: em, email: em, name: user.name, isAdmin: false, isSubscriber,
      exp: Math.floor(Date.now() / 1000) + 86400 * 30 },
    env.JWT_SECRET
  );
  await logEvent(env, em, 'login', { name: user.name });
  return ok({ token, isAdmin: false, isSubscriber, name: user.name });
}

// ── REGISTER ─────────────────────────────────────────────────
async function register(request, env) {
  const { name, email, password } = await request.json();
  if (!name || !email || !password) return fail('Tous les champs sont requis');
  if (password.length < 6) return fail('Mot de passe trop court (6 caractères min)');
  const em = email.toLowerCase().trim();

  if (await env.JADIS_DATA.get(`user:${em}`)) return fail('Un compte existe déjà avec cet email');

  const passwordHash = await hashPwd(password);
  const now = new Date().toISOString();
  await env.JADIS_DATA.put(`user:${em}`, JSON.stringify({ name, email: em, passwordHash, createdAt: now, lastLogin: now }));

  // Mise à jour index
  const idx = (await env.JADIS_DATA.get('users_index', 'json')) || [];
  if (!idx.includes(em)) { idx.push(em); await env.JADIS_DATA.put('users_index', JSON.stringify(idx)); }

  const token = await signJWT(
    { userId: em, email: em, name, isAdmin: false, isSubscriber: false,
      exp: Math.floor(Date.now() / 1000) + 86400 * 30 },
    env.JWT_SECRET
  );
  await logEvent(env, em, 'register', { name });
  return ok({ token, isAdmin: false, isSubscriber: false, name });
}

// ── VERIFY ───────────────────────────────────────────────────
async function verify(request, env) {
  const session = await getSession(request, env);
  if (!session) return fail('Token invalide', 401);
  // Rafraîchit isSubscriber depuis KV pour les non-admins
  if (!session.isAdmin) {
    session.isSubscriber = !!(await env.JADIS_DATA.get(`subscriber:${session.email}`));
  }
  return ok({ valid: true, ...session });
}

// ── USER SAVE ────────────────────────────────────────────────
async function userSave(request, env) {
  const session = await getSession(request, env);
  if (!session) return fail('Non authentifié', 401);
  const body = await request.json();
  const key = `userdata:${session.userId}`;
  const existing = (await env.JADIS_DATA.get(key, 'json')) || {};
  await env.JADIS_DATA.put(key, JSON.stringify({ ...existing, ...body, updatedAt: new Date().toISOString() }));
  return ok({ ok: true });
}

// ── USER DATA ────────────────────────────────────────────────
async function userData(request, env) {
  const session = await getSession(request, env);
  if (!session) return fail('Non authentifié', 401);
  const data = (await env.JADIS_DATA.get(`userdata:${session.userId}`, 'json')) || {};
  return ok(data);
}

// ── ADMIN : LISTE UTILISATEURS ───────────────────────────────
async function adminUsers(request, env) {
  const session = await getSession(request, env);
  if (!session?.isAdmin) return fail('Accès refusé', 403);

  const idx = (await env.JADIS_DATA.get('users_index', 'json')) || [];
  const subsIdx = new Set((await env.JADIS_DATA.get('subscribers_index', 'json')) || []);

  const users = await Promise.all(idx.map(async em => {
    const u = (await env.JADIS_DATA.get(`user:${em}`, 'json')) || { email: em };
    return { name: u.name || '—', email: em, createdAt: u.createdAt || null, lastLogin: u.lastLogin || null, isSubscriber: subsIdx.has(em) };
  }));

  // Tri : les plus récents en premier
  users.sort((a, b) => (b.createdAt || '') > (a.createdAt || '') ? 1 : -1);

  return ok({ users, total: users.length, totalSubscribers: subsIdx.size });
}

// ── ADMIN : STATS ────────────────────────────────────────────
async function adminStats(request, env) {
  const session = await getSession(request, env);
  if (!session?.isAdmin) return fail('Accès refusé', 403);

  const [idx, subsIdx, events, pageviews] = await Promise.all([
    env.JADIS_DATA.get('users_index', 'json'),
    env.JADIS_DATA.get('subscribers_index', 'json'),
    env.JADIS_DATA.get('events', 'json'),
    env.JADIS_DATA.get('pageviews', 'json')
  ]);

  const users = idx || [];
  const subs = subsIdx || [];
  const evts = events || [];
  const pvs = pageviews || [];
  const today = new Date().toISOString().split('T')[0];

  return ok({
    totalUsers: users.length,
    totalSubscribers: subs.length,
    totalFree: Math.max(0, users.length - subs.length),
    totalPageviews: pvs.length,
    todayPageviews: pvs.filter(p => (p.timestamp || '').startsWith(today)).length,
    recentEvents: evts.slice(-200).reverse()
  });
}

// ── ADMIN : ÉVÉNEMENTS ───────────────────────────────────────
async function adminEvents(request, env) {
  const session = await getSession(request, env);
  if (!session?.isAdmin) return fail('Accès refusé', 403);
  const evts = (await env.JADIS_DATA.get('events', 'json')) || [];
  return ok({ events: evts.slice(-100).reverse() });
}

// ── ADMIN : GRANT ────────────────────────────────────────────
async function adminGrant(request, env) {
  const session = await getSession(request, env);
  if (!session?.isAdmin) return fail('Accès refusé', 403);

  const { email, name } = await request.json();
  if (!email) return fail('Email requis');
  const em = email.toLowerCase().trim();

  await env.JADIS_DATA.put(`subscriber:${em}`, JSON.stringify({ email: em, addedAt: new Date().toISOString(), addedBy: session.email }));

  // Crée le compte si inexistant
  if (!(await env.JADIS_DATA.get(`user:${em}`))) {
    const now = new Date().toISOString();
    await env.JADIS_DATA.put(`user:${em}`, JSON.stringify({ name: name || em.split('@')[0], email: em, createdAt: now, lastLogin: now }));
    const idx = (await env.JADIS_DATA.get('users_index', 'json')) || [];
    if (!idx.includes(em)) { idx.push(em); await env.JADIS_DATA.put('users_index', JSON.stringify(idx)); }
  }

  const subsIdx = (await env.JADIS_DATA.get('subscribers_index', 'json')) || [];
  if (!subsIdx.includes(em)) { subsIdx.push(em); await env.JADIS_DATA.put('subscribers_index', JSON.stringify(subsIdx)); }

  await logEvent(env, em, 'access_granted', { by: session.email });
  return ok({ ok: true });
}

// ── ADMIN : REVOKE ───────────────────────────────────────────
async function adminRevoke(request, env) {
  const session = await getSession(request, env);
  if (!session?.isAdmin) return fail('Accès refusé', 403);

  const { email } = await request.json();
  if (!email) return fail('Email requis');
  const em = email.toLowerCase().trim();

  await env.JADIS_DATA.delete(`subscriber:${em}`);
  const subsIdx = ((await env.JADIS_DATA.get('subscribers_index', 'json')) || []).filter(e => e !== em);
  await env.JADIS_DATA.put('subscribers_index', JSON.stringify(subsIdx));

  await logEvent(env, em, 'access_revoked', { by: session.email });
  return ok({ ok: true });
}

// ── TRACKING ─────────────────────────────────────────────────
async function track(request, env) {
  const body = await request.json().catch(() => ({}));
  if (body.type === 'pageview') {
    const pvs = (await env.JADIS_DATA.get('pageviews', 'json')) || [];
    pvs.push({
      page: body.page || '/',
      timestamp: new Date().toISOString(),
      sessionId: body.sessionId || '',
      referrer: body.referrer || 'direct',
      ua: (request.headers.get('User-Agent') || '').substring(0, 100)
    });
    if (pvs.length > 5000) pvs.splice(0, pvs.length - 5000);
    await env.JADIS_DATA.put('pageviews', JSON.stringify(pvs));
  }
  return ok({ ok: true });
}

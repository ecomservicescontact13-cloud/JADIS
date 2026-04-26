// ═══════════════════════════════════════════════════════════════
//  JADIS — Cloudflare Pages Function (_worker.js)
//  Backend : Supabase PostgreSQL (remplace Cloudflare KV)
//
//  CONFIGURATION dans Cloudflare Pages → Settings → Environment variables :
//  1. SUPABASE_URL  → https://xlvynoqrpquzdnbwzeex.supabase.co
//  2. SUPABASE_KEY  → (service_role key — jamais exposée côté client)
//  3. JWT_SECRET    → jadis2026xSecretClef!Immuable$Forte
//
//  Le binding KV "JADIS_DATA" peut être retiré — plus utilisé.
// ═══════════════════════════════════════════════════════════════

const ADMIN_EMAILS = ['issamboussalah131@gmail.com', 'shanedarren42@gmail.com'];

const ALLOWED_ORIGINS = [
  'https://jadis.pages.dev',
  'http://localhost',
  'http://127.0.0.1'
];

function getCORS(request) {
  const origin = (request.headers.get('Origin') || '');
  const allowed = ALLOWED_ORIGINS.some(o => origin.startsWith(o)) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, PATCH, OPTIONS',
    'Access-Control-Allow-Credentials': 'true',
    'Content-Type': 'application/json'
  };
}

let _req = null;

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

// ── Hachage de mot de passe (PBKDF2) ────────────────────────
async function hashPwd(pwd, saltB64 = null) {
  const enc = new TextEncoder();
  const salt = saltB64 ? db64u(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(pwd), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256
  );
  return `${ab64u(salt)}:${ab64u(bits)}`;
}

async function verifyPwd(pwd, stored) {
  const [salt] = stored.split(':');
  return (await hashPwd(pwd, salt)) === stored;
}

async function getSession(request, env) {
  const auth = (request.headers.get('Authorization') || '').replace('Bearer ', '');
  if (!auth) return null;
  try { return await verifyJWT(auth, env.JWT_SECRET); }
  catch { return null; }
}

// ── Supabase REST helper ──────────────────────────────────────
async function sb(env, path, method = 'GET', body = null, extraHeaders = {}) {
  const url = `${env.SUPABASE_URL}/rest/v1/${path}`;
  const res = await fetch(url, {
    method,
    headers: {
      'apikey': env.SUPABASE_KEY,
      'Authorization': `Bearer ${env.SUPABASE_KEY}`,
      'Content-Type': 'application/json',
      ...extraHeaders
    },
    body: body ? JSON.stringify(body) : null
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Supabase ${method} /${path} → ${res.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}

// ── Log d'événement ──────────────────────────────────────────
async function logEvent(env, email, type, extra = {}) {
  try {
    await sb(env, 'events', 'POST', {
      email,
      type,
      name:     extra.name    || null,
      is_admin: extra.isAdmin || false,
      timestamp: new Date().toISOString()
    }, { 'Prefer': 'return=minimal' });
  } catch (_) {}
}

// ════════════════════════════════════════════════════════════════
//  ROUTER PRINCIPAL
// ════════════════════════════════════════════════════════════════
export default {
  async fetch(request, env, ctx) {
    _req = request;

    // Preflight CORS
    if (request.method === 'OPTIONS') {
      return new Response('', { headers: getCORS(request) });
    }

    const url  = new URL(request.url);
    const path = url.pathname.replace(/^\/+/, '');
    const m    = request.method;

    // Fichiers statiques → servis par Pages directement
    const staticExts = /\.(html|css|js|svg|png|jpg|jpeg|gif|ico|woff|woff2|ttf|json)$/i;
    if (staticExts.test(path) || path === '' || path === 'index.html') {
      return env.ASSETS.fetch(request);
    }

    try {
      if (path === 'auth/login'    && m === 'POST')  return await login(request, env);
      if (path === 'auth/register' && m === 'POST')  return await register(request, env);
      if (path === 'auth/verify'   && m === 'POST')  return await verify(request, env);
      if (path === 'auth/check-email' && m === 'POST') return await checkEmail(request, env);
      if (path === 'user/save'     && m === 'POST')  return await userSave(request, env);
      if (path === 'user/data'     && m === 'GET')   return await userData(request, env);
      if (path === 'admin/users'   && m === 'GET')   return await adminUsers(request, env);
      if (path === 'admin/stats'   && m === 'GET')   return await adminStats(request, env);
      if (path === 'admin/events'  && m === 'GET')   return await adminEvents(request, env);
      if (path === 'admin/grant'   && m === 'POST')  return await adminGrant(request, env);
      if (path === 'admin/revoke'  && m === 'POST')  return await adminRevoke(request, env);
      if (path === 'track'         && m === 'POST')  return await track(request, env);

      return env.ASSETS.fetch(request);
    } catch (e) {
      console.error('Worker error:', e);
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

  const rows = await sb(env, `users?email=eq.${encodeURIComponent(em)}&select=*`);
  if (!rows || rows.length === 0) return fail('Aucun compte avec cet email', 401);
  const user = rows[0];

  const valid = await verifyPwd(password, user.password_hash);
  if (!valid) return fail('Mot de passe incorrect', 401);

  // last_login update skipped (schema cache)

  const subRows = await sb(env, `subscribers?email=eq.${encodeURIComponent(em)}&select=email`);
  const isSubscriber = !!(subRows && subRows.length > 0);

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

  const existing = await sb(env, `users?email=eq.${encodeURIComponent(em)}&select=email`);
  if (existing && existing.length > 0) return fail('Un compte existe déjà avec cet email');

  const passwordHash = await hashPwd(password);
  const now = new Date().toISOString();
  await sb(env, 'users', 'POST',
    { id: crypto.randomUUID(), email: em, name, password_hash: passwordHash, created_at: now },
    { 'Prefer': 'return=minimal' }
  );

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
  if (!session.isAdmin) {
    const subRows = await sb(env, `subscribers?email=eq.${encodeURIComponent(session.email)}&select=email`);
    session.isSubscriber = !!(subRows && subRows.length > 0);
  }
  return ok({ valid: true, ...session });
}

// ── USER SAVE ────────────────────────────────────────────────
async function userSave(request, env) {
  const session = await getSession(request, env);
  if (!session) return fail('Non authentifié', 401);
  const body = await request.json();

  const existing = await sb(env, `user_data?email=eq.${encodeURIComponent(session.userId)}&select=data`);
  const current  = (existing && existing.length > 0) ? (existing[0].data || {}) : {};
  const merged   = { ...current, ...body };

  if (existing && existing.length > 0) {
    await sb(env,
      `user_data?email=eq.${encodeURIComponent(session.userId)}`, 'PATCH',
      { data: merged, updated_at: new Date().toISOString() },
      { 'Prefer': 'return=minimal' }
    );
  } else {
    await sb(env, 'user_data', 'POST',
      { email: session.userId, data: merged, updated_at: new Date().toISOString() },
      { 'Prefer': 'return=minimal' }
    );
  }
  return ok({ ok: true });
}

// ── USER DATA ────────────────────────────────────────────────
async function userData(request, env) {
  const session = await getSession(request, env);
  if (!session) return fail('Non authentifié', 401);
  const rows = await sb(env, `user_data?email=eq.${encodeURIComponent(session.userId)}&select=data`);
  return ok((rows && rows.length > 0) ? (rows[0].data || {}) : {});
}

// ── ADMIN : LISTE UTILISATEURS ───────────────────────────────
async function adminUsers(request, env) {
  const session = await getSession(request, env);
  if (!session?.isAdmin) return fail('Accès refusé', 403);

  const [users, subs] = await Promise.all([
    sb(env, 'users?select=email,name,created_at&order=created_at.desc'),
    sb(env, 'subscribers?select=email')
  ]);

  const subSet = new Set((subs || []).map(s => s.email));
  const result = (users || []).map(u => ({
    name:         u.name || '—',
    email:        u.email,
    createdAt:    u.created_at,
    
    isSubscriber: subSet.has(u.email)
  }));

  return ok({ users: result, total: result.length, totalSubscribers: subSet.size });
}

// ── ADMIN : STATS ────────────────────────────────────────────
async function adminStats(request, env) {
  const session = await getSession(request, env);
  if (!session?.isAdmin) return fail('Accès refusé', 403);

  const today = new Date().toISOString().split('T')[0];

  const [users, subs, events, pageviews] = await Promise.all([
    sb(env, 'users?select=email'),
    sb(env, 'subscribers?select=email'),
    sb(env, 'events?select=email,name,type,timestamp&order=timestamp.desc&limit=200'),
    sb(env, 'pageviews?select=timestamp&order=timestamp.desc&limit=5000')
  ]);

  const pvs  = pageviews || [];
  const evts = events   || [];

  return ok({
    totalUsers:        (users || []).length,
    totalSubscribers:  (subs  || []).length,
    totalFree:         Math.max(0, (users || []).length - (subs || []).length),
    totalPageviews:    pvs.length,
    todayPageviews:    pvs.filter(p => (p.timestamp || '').startsWith(today)).length,
    recentEvents:      evts
  });
}

// ── ADMIN : ÉVÉNEMENTS ───────────────────────────────────────
async function adminEvents(request, env) {
  const session = await getSession(request, env);
  if (!session?.isAdmin) return fail('Accès refusé', 403);
  const events = await sb(env, 'events?select=*&order=timestamp.desc&limit=100');
  return ok({ events: events || [] });
}

// ── ADMIN : GRANT ────────────────────────────────────────────
async function adminGrant(request, env) {
  const session = await getSession(request, env);
  if (!session?.isAdmin) return fail('Accès refusé', 403);

  const { email, name } = await request.json();
  if (!email) return fail('Email requis');
  const em  = email.toLowerCase().trim();
  const now = new Date().toISOString();

  // Upsert subscriber
  await sb(env, 'subscribers', 'POST',
    { email: em, added_at: now, added_by: session.email },
    { 'Prefer': 'resolution=merge-duplicates,return=minimal' }
  );

  // Créer le compte utilisateur s'il n'existe pas encore
  const existing = await sb(env, `users?email=eq.${encodeURIComponent(em)}&select=email`);
  if (!existing || existing.length === 0) {
    await sb(env, 'users', 'POST',
      { id: crypto.randomUUID(), email: em, name: name || em.split('@')[0], created_at: now },
      { 'Prefer': 'return=minimal' }
    );
  }

  await logEvent(env, em, 'access_granted', { name: name || em.split('@')[0] });
  return ok({ ok: true });
}

// ── ADMIN : REVOKE ───────────────────────────────────────────
async function adminRevoke(request, env) {
  const session = await getSession(request, env);
  if (!session?.isAdmin) return fail('Accès refusé', 403);

  const { email } = await request.json();
  if (!email) return fail('Email requis');
  const em = email.toLowerCase().trim();

  await sb(env, `subscribers?email=eq.${encodeURIComponent(em)}`, 'DELETE');
  await logEvent(env, em, 'access_revoked');
  return ok({ ok: true });
}

// ── TRACKING ─────────────────────────────────────────────────
async function track(request, env) {
  const body = await request.json().catch(() => ({}));
  if (body.type === 'pageview') {
    await sb(env, 'pageviews', 'POST', {
      page:       body.page      || '/',
      session_id: body.sessionId || '',
      referrer:   body.referrer  || 'direct',
      ua:         (request.headers.get('User-Agent') || '').substring(0, 100),
      timestamp:  new Date().toISOString()
    }, { 'Prefer': 'return=minimal' }).catch(() => {});
  }
  return ok({ ok: true });
}

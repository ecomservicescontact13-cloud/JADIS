-- ═══════════════════════════════════════════════════════════════
--  JADIS — Schéma Supabase
--  Colle ce script dans : Supabase Dashboard → SQL Editor → New query
--  puis clique sur "Run"
-- ═══════════════════════════════════════════════════════════════

-- ── Utilisateurs inscrits ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.users (
  email         TEXT PRIMARY KEY,
  name          TEXT,
  password_hash TEXT,
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  last_login    TIMESTAMPTZ
);

-- ── Abonnés premium ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.subscribers (
  email     TEXT PRIMARY KEY,
  added_at  TIMESTAMPTZ DEFAULT NOW(),
  added_by  TEXT
);

-- ── Événements (login / inscription / access_granted ...) ─────
CREATE TABLE IF NOT EXISTS public.events (
  id        BIGSERIAL PRIMARY KEY,
  email     TEXT,
  type      TEXT,
  name      TEXT,
  is_admin  BOOLEAN DEFAULT FALSE,
  timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- ── Tracking de pages vues ────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.pageviews (
  id         BIGSERIAL PRIMARY KEY,
  page       TEXT,
  session_id TEXT,
  referrer   TEXT,
  ua         TEXT,
  timestamp  TIMESTAMPTZ DEFAULT NOW()
);

-- ── Données utilisateur (progression dashboard) ───────────────
CREATE TABLE IF NOT EXISTS public.user_data (
  email      TEXT PRIMARY KEY,
  data       JSONB DEFAULT '{}',
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── Désactiver RLS (accès uniquement via service_role depuis le Worker) ──
ALTER TABLE public.users      DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.subscribers DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.events     DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.pageviews  DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_data  DISABLE ROW LEVEL SECURITY;

-- ── Index pour les performances ───────────────────────────────
CREATE INDEX IF NOT EXISTS idx_events_timestamp    ON public.events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_pageviews_timestamp ON public.pageviews(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_email        ON public.events(email);

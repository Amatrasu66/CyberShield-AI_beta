-- CyberShield AI Supabase PostgreSQL Database Schema
--
-- Supabase Auth manages the authentication user store in `auth.users`.
-- There is NO `public.users` table and password hashes are never stored in
-- the application database. Application user data lives in `public.profiles`,
-- linked 1:1 to `auth.users.id`.
--
-- Run this in the Supabase SQL editor. It is idempotent (IF NOT EXISTS).

-- ============================================================================
-- Profiles (1:1 with auth.users)
-- ============================================================================
CREATE TABLE IF NOT EXISTS profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    full_name TEXT,
    role TEXT CHECK (role IN ('Student', 'Faculty', 'Internship Evaluator')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ
);

-- Auto-create a profile when a new user signs up via Supabase Auth.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    INSERT INTO public.profiles (id)
    VALUES (NEW.id)
    ON CONFLICT (id) DO NOTHING;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ============================================================================
-- Website Scans
-- ============================================================================
CREATE TABLE IF NOT EXISTS website_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    target_url TEXT NOT NULL,
    status TEXT CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    security_score INT CHECK (security_score >= 0 AND security_score <= 100),
    risk_level TEXT CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    findings JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- Email Scans
-- Raw email content is not persisted; only findings/indicators and metadata.
-- ============================================================================
CREATE TABLE IF NOT EXISTS email_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    subject TEXT,
    sender_email TEXT,
    predicted_label TEXT CHECK (predicted_label IN ('phishing', 'safe')),
    confidence FLOAT,
    risk_level TEXT CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    indicators JSONB,
    model_version TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- Password Scans
-- Derived metrics only. The analyzed password or its hash are never stored.
-- ============================================================================
CREATE TABLE IF NOT EXISTS password_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    password_length INT,
    entropy FLOAT,
    strength_score INT CHECK (strength_score >= 0 AND strength_score <= 100),
    strength_label TEXT,
    has_upper BOOLEAN,
    has_lower BOOLEAN,
    has_number BOOLEAN,
    has_symbol BOOLEAN,
    breached BOOLEAN,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- Log Scans
-- Raw log content is not persisted; only findings/results and metadata.
-- ============================================================================
CREATE TABLE IF NOT EXISTS log_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    event_count INT,
    anomaly_count INT,
    findings JSONB,
    risk_level TEXT CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    model_version TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- Port Scans
-- TCP connect scan results with per-port findings and risk scoring.
-- ============================================================================
CREATE TABLE IF NOT EXISTS port_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    resolved_ip TEXT,
    ports_scanned INT NOT NULL,
    open_ports JSONB,
    scan_duration_ms INT,
    risk_level TEXT CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    status TEXT CHECK (status IN ('completed', 'failed')) NOT NULL DEFAULT 'completed',
    ip_reputation JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Backfill for existing databases that already have port_scans without ip_reputation
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'port_scans' AND column_name = 'ip_reputation'
    ) THEN
        ALTER TABLE port_scans ADD COLUMN ip_reputation JSONB;
    END IF;
END $$;

-- ============================================================================
-- IP Reputation Cache (shared, not per-user)
-- Shared provider data; no user_id, no API keys, no tokens.
-- ============================================================================
CREATE TABLE IF NOT EXISTS ip_reputation_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip TEXT NOT NULL,
    reputation TEXT NOT NULL CHECK (reputation IN ('unknown','clean','suspicious','malicious','unavailable')),
    confidence TEXT NOT NULL CHECK (confidence IN ('none','low','medium','high','very_high')),
    malicious BOOLEAN NOT NULL DEFAULT FALSE,
    suspicious BOOLEAN NOT NULL DEFAULT FALSE,
    reports INT NOT NULL DEFAULT 0,
    country TEXT,
    asn TEXT,
    organization TEXT,
    isp TEXT,
    last_reported_at TIMESTAMPTZ,
    provider TEXT NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ip_reputation_cache_ip_provider_unique UNIQUE (ip, provider)
);

CREATE INDEX IF NOT EXISTS idx_ip_reputation_cache_ip_provider
    ON ip_reputation_cache (ip, provider);
CREATE INDEX IF NOT EXISTS idx_ip_reputation_cache_expires_at
    ON ip_reputation_cache (expires_at);

-- Shared cache: enable RLS but allow only service_role to bypass.
-- No policies for anon/authenticated → frontend cannot read/write directly.
-- Backend uses service_role (get_supabase_admin_client) which bypasses RLS.
ALTER TABLE ip_reputation_cache ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- Reports
-- ============================================================================
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    report_type TEXT CHECK (report_type IN ('pdf')),
    storage_path TEXT,
    report_data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- Indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_website_scans_user_created
    ON website_scans (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_scans_user_created
    ON email_scans (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_password_scans_user_created
    ON password_scans (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_log_scans_user_created
    ON log_scans (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_port_scans_user_created
    ON port_scans (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_user_created
    ON reports (user_id, created_at DESC);

-- ============================================================================
-- Row Level Security
-- All scan tables and reports are user-scoped via auth.uid().
-- ============================================================================
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE website_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE log_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE port_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;

-- profiles: owner-only SELECT / UPDATE (INSERT handled by the signup trigger).
DROP POLICY IF EXISTS "profiles_select_own" ON profiles;
CREATE POLICY "profiles_select_own" ON profiles
    FOR SELECT USING (id = auth.uid());
DROP POLICY IF EXISTS "profiles_update_own" ON profiles;
CREATE POLICY "profiles_update_own" ON profiles
    FOR UPDATE USING (id = auth.uid()) WITH CHECK (id = auth.uid());

-- Scan tables and reports: owner-only SELECT / INSERT / UPDATE / DELETE.
DROP POLICY IF EXISTS "website_scans_owner_all" ON website_scans;
CREATE POLICY "website_scans_owner_all" ON website_scans
    FOR ALL USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

DROP POLICY IF EXISTS "email_scans_owner_all" ON email_scans;
CREATE POLICY "email_scans_owner_all" ON email_scans
    FOR ALL USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

DROP POLICY IF EXISTS "password_scans_owner_all" ON password_scans;
CREATE POLICY "password_scans_owner_all" ON password_scans
    FOR ALL USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

DROP POLICY IF EXISTS "log_scans_owner_all" ON log_scans;
CREATE POLICY "log_scans_owner_all" ON log_scans
    FOR ALL USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

DROP POLICY IF EXISTS "port_scans_owner_all" ON port_scans;
CREATE POLICY "port_scans_owner_all" ON port_scans
    FOR ALL USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

DROP POLICY IF EXISTS "reports_owner_all" ON reports;
CREATE POLICY "reports_owner_all" ON reports
    FOR ALL USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

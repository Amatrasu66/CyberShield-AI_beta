-- CyberShield AI Supabase PostgreSQL Initial Database Schema (Placeholder)

-- Users Table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Website Scans Table
CREATE TABLE IF NOT EXISTS website_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    target_url TEXT NOT NULL,
    scan_result JSONB,
    score INT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Email Scans Table
CREATE TABLE IF NOT EXISTS email_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    email_text TEXT NOT NULL,
    is_phishing BOOLEAN,
    confidence FLOAT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Password Scans Table
CREATE TABLE IF NOT EXISTS password_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    entropy_score FLOAT,
    strength_rating TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Log Scans Table
CREATE TABLE IF NOT EXISTS log_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    log_summary JSONB,
    anomalies_detected INT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Reports Table
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    report_name TEXT NOT NULL,
    file_path TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

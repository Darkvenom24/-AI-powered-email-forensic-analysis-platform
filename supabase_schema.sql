-- ============================================================
-- SIH26106: AI Email Forensic Analysis Platform
-- Supabase PostgreSQL Schema
-- ============================================================

-- 1. Enable UUID extension if not enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 2. Investigations Table
CREATE TABLE IF NOT EXISTS investigations (
    id BIGSERIAL PRIMARY KEY,
    case_id TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    timestamp TEXT NOT NULL,
    sender TEXT DEFAULT '',
    receiver TEXT DEFAULT '',
    subject TEXT DEFAULT '',
    prediction TEXT DEFAULT 'UNKNOWN',
    confidence REAL DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    threat_level TEXT DEFAULT 'UNKNOWN',
    risk_reasons JSONB DEFAULT '[]'::jsonb,
    forensic_data JSONB DEFAULT '{}'::jsonb,
    ioc_data JSONB DEFAULT '{}'::jsonb,
    attachment_data JSONB DEFAULT '{}'::jsonb,
    timeline_data JSONB DEFAULT '[]'::jsonb,
    raw_snippet TEXT DEFAULT ''
);

-- Indexes for lightning-fast queries on Vercel
CREATE INDEX IF NOT EXISTS idx_investigations_case_id ON investigations(case_id);
CREATE INDEX IF NOT EXISTS idx_investigations_threat_level ON investigations(threat_level);
CREATE INDEX IF NOT EXISTS idx_investigations_prediction ON investigations(prediction);
CREATE INDEX IF NOT EXISTS idx_investigations_risk_score ON investigations(risk_score);
CREATE INDEX IF NOT EXISTS idx_investigations_created_at ON investigations(created_at DESC);

-- 3. Indicators of Compromise (IOCs) Catalog
CREATE TABLE IF NOT EXISTS ioc_catalog (
    id BIGSERIAL PRIMARY KEY,
    ioc_type TEXT NOT NULL, -- 'ip', 'domain', 'url', 'hash', 'email'
    ioc_value TEXT NOT NULL,
    threat_score INTEGER DEFAULT 50,
    source_case_id TEXT REFERENCES investigations(case_id) ON DELETE SET NULL,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    reputation TEXT DEFAULT 'suspicious',
    notes TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc_catalog(ioc_value);
CREATE INDEX IF NOT EXISTS idx_ioc_type ON ioc_catalog(ioc_type);

-- 4. Platform Settings & Integration Cache
CREATE TABLE IF NOT EXISTS platform_settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default system metadata
INSERT INTO platform_settings (key, value)
VALUES 
    ('system_info', '{"platform": "SIH26106 Email Forensic Intelligence", "version": "1.0.0", "ai_model": "TF-IDF + Logistic Regression"}'::jsonb),
    ('stats_cache', '{"total": 0, "phishing": 0, "spam": 0, "safe": 0, "high_risk": 0}'::jsonb)
ON CONFLICT (key) DO NOTHING;

-- 5. Row Level Security (RLS) policies (Optional: enable public anon access for hackathon prototype)
ALTER TABLE investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ioc_catalog ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_settings ENABLE ROW LEVEL SECURITY;

-- Allow anon read & insert for hackathon demo
CREATE POLICY "Allow public read investigations" ON investigations FOR SELECT USING (true);
CREATE POLICY "Allow public insert investigations" ON investigations FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow public delete investigations" ON investigations FOR DELETE USING (true);

CREATE POLICY "Allow public read ioc_catalog" ON ioc_catalog FOR SELECT USING (true);
CREATE POLICY "Allow public insert ioc_catalog" ON ioc_catalog FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow public read platform_settings" ON platform_settings FOR SELECT USING (true);
CREATE POLICY "Allow public upsert platform_settings" ON platform_settings FOR ALL USING (true);

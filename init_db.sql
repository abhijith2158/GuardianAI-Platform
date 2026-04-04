CREATE TABLE IF NOT EXISTS developers (
    id BIGSERIAL PRIMARY KEY,
    api_key TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,
    developer_id BIGINT NOT NULL REFERENCES developers(id) ON DELETE CASCADE,
    ts TIMESTAMPTZ NOT NULL,
    service TEXT NOT NULL,
    env TEXT NOT NULL,
    event_type TEXT NOT NULL,
    verdict TEXT,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_events_created_at
ON security_events (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_developer_created
ON security_events (developer_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_service
ON security_events (service);

CREATE INDEX IF NOT EXISTS idx_security_events_verdict
ON security_events (verdict);

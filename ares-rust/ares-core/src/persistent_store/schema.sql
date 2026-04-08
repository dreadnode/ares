-- Ares Persistent Store Schema
--
-- PostgreSQL schema for long-term operation data storage.
-- Tables use UUID primary keys for consistency with Redis data.
-- This schema supports both red team operation offload and blue team investigations.

-- ============================================================================
-- Operations
-- ============================================================================

CREATE TABLE IF NOT EXISTS operations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id    TEXT NOT NULL UNIQUE,
    target_ip       INET,
    target_domain   TEXT,
    environment     TEXT,
    started_at      TIMESTAMPTZ NOT NULL,
    completed_at    TIMESTAMPTZ,
    has_domain_admin    BOOLEAN NOT NULL DEFAULT FALSE,
    has_golden_ticket   BOOLEAN NOT NULL DEFAULT FALSE,
    domain_admin_path   TEXT,
    da_hash_id          TEXT,
    final_report        TEXT,
    config              JSONB,

    -- Aggregated stats (computed on offload)
    credential_count    INTEGER,
    hash_count          INTEGER,
    host_count          INTEGER,
    vulnerability_count INTEGER,
    exploited_vulnerability_count INTEGER,

    -- Cost tracking
    total_input_tokens  BIGINT,
    total_output_tokens BIGINT,
    total_cost          DOUBLE PRECISION,
    model_usage         JSONB,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_operations_started_at ON operations (started_at);
CREATE INDEX IF NOT EXISTS idx_operations_domain ON operations (target_domain);
CREATE INDEX IF NOT EXISTS idx_operations_da ON operations (has_domain_admin);

-- ============================================================================
-- Credentials
-- ============================================================================

CREATE TABLE IF NOT EXISTS credentials (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id        UUID NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    credential_id       TEXT,
    username            TEXT NOT NULL,
    domain              TEXT,
    password_hash       TEXT,
    password_encrypted  TEXT,
    is_admin            BOOLEAN NOT NULL DEFAULT FALSE,
    source              TEXT,
    parent_credential_id UUID REFERENCES credentials(id) ON DELETE SET NULL,
    attack_step         INTEGER NOT NULL DEFAULT 0,
    discovered_at       TIMESTAMPTZ,
    extra_data          JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE credentials DROP CONSTRAINT IF EXISTS uq_cred;
ALTER TABLE credentials ADD CONSTRAINT uq_cred
    UNIQUE (operation_id, domain, username, password_hash);

CREATE INDEX IF NOT EXISTS idx_credentials_operation ON credentials (operation_id);
CREATE INDEX IF NOT EXISTS idx_credentials_domain_user ON credentials (domain, username);

-- ============================================================================
-- Hashes
-- ============================================================================

CREATE TABLE IF NOT EXISTS hashes (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id        UUID NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    hash_id             TEXT,
    username            TEXT NOT NULL,
    domain              TEXT,
    hash_type           TEXT,
    hash_value_prefix   TEXT,
    hash_value_encrypted TEXT,
    cracked_password_hash TEXT,
    source              TEXT,
    parent_hash_id      UUID REFERENCES hashes(id) ON DELETE SET NULL,
    attack_step         INTEGER NOT NULL DEFAULT 0,
    discovered_at       TIMESTAMPTZ,
    extra_data          JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE hashes DROP CONSTRAINT IF EXISTS uq_hash;
ALTER TABLE hashes ADD CONSTRAINT uq_hash
    UNIQUE (operation_id, domain, username, hash_type, hash_value_prefix);

CREATE INDEX IF NOT EXISTS idx_hashes_operation ON hashes (operation_id);
CREATE INDEX IF NOT EXISTS idx_hashes_type ON hashes (hash_type);

-- ============================================================================
-- Hosts
-- ============================================================================

CREATE TABLE IF NOT EXISTS hosts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id    UUID NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    ip              INET NOT NULL,
    hostname        TEXT,
    fqdn            TEXT,
    os              TEXT,
    is_dc           BOOLEAN NOT NULL DEFAULT FALSE,
    is_owned        BOOLEAN NOT NULL DEFAULT FALSE,
    roles           TEXT[],
    services        TEXT[],
    discovered_at   TIMESTAMPTZ,
    extra_data      JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE hosts DROP CONSTRAINT IF EXISTS uq_host;
ALTER TABLE hosts ADD CONSTRAINT uq_host UNIQUE (operation_id, ip);

CREATE INDEX IF NOT EXISTS idx_hosts_operation ON hosts (operation_id);
CREATE INDEX IF NOT EXISTS idx_hosts_dc ON hosts (is_dc);

-- ============================================================================
-- Users
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id    UUID NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    username        TEXT NOT NULL,
    domain          TEXT,
    description     TEXT,
    is_admin        BOOLEAN NOT NULL DEFAULT FALSE,
    source          TEXT,
    discovered_at   TIMESTAMPTZ,
    extra_data      JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE users DROP CONSTRAINT IF EXISTS uq_user;
ALTER TABLE users ADD CONSTRAINT uq_user UNIQUE (operation_id, domain, username);

CREATE INDEX IF NOT EXISTS idx_users_operation ON users (operation_id);

-- ============================================================================
-- Vulnerabilities
-- ============================================================================

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id        UUID NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    vuln_id             TEXT NOT NULL,
    vuln_type           TEXT NOT NULL,
    target_ip           INET,
    target_hostname     TEXT,
    priority            INTEGER,
    discovered_by       TEXT,
    discovered_at       TIMESTAMPTZ,
    exploited_at        TIMESTAMPTZ,
    exploitation_result TEXT,
    details             JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS uq_vuln;
ALTER TABLE vulnerabilities ADD CONSTRAINT uq_vuln UNIQUE (operation_id, vuln_id);

CREATE INDEX IF NOT EXISTS idx_vulns_operation ON vulnerabilities (operation_id);
CREATE INDEX IF NOT EXISTS idx_vulns_type ON vulnerabilities (vuln_type);

-- ============================================================================
-- Timeline Events
-- ============================================================================

CREATE TABLE IF NOT EXISTS timeline_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id        UUID NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    event_id            TEXT,
    timestamp           TIMESTAMPTZ NOT NULL,
    description         TEXT,
    mitre_techniques    TEXT[],
    confidence          DOUBLE PRECISION,
    source              TEXT,
    evidence_ids        TEXT[],
    extra_data          JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_timeline_operation_time ON timeline_events (operation_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_timeline_techniques ON timeline_events USING GIN (mitre_techniques);

-- ============================================================================
-- Artifacts
-- ============================================================================

CREATE TABLE IF NOT EXISTS artifacts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id    UUID NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    artifact_key    TEXT NOT NULL,
    content_type    TEXT,
    size_bytes      INTEGER,
    content_hash    TEXT,
    content_base64  TEXT,
    storage_path    TEXT,
    discovered_at   TIMESTAMPTZ,
    extra_data      JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE artifacts DROP CONSTRAINT IF EXISTS uq_artifact;
ALTER TABLE artifacts ADD CONSTRAINT uq_artifact UNIQUE (operation_id, artifact_key);

CREATE INDEX IF NOT EXISTS idx_artifacts_operation ON artifacts (operation_id);

-- ============================================================================
-- Investigations (cross-operation grouping)
-- ============================================================================

CREATE TABLE IF NOT EXISTS investigations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    description     TEXT,
    operation_ids   UUID[],
    status          TEXT NOT NULL DEFAULT 'active',
    findings        JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      TEXT
);

CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations (status);

CREATE TABLE credential (
 id uuid PRIMARY KEY,
 application text NOT NULL,
 subject text NOT NULL,
 rp_id text NOT NULL,
 webauthn_id bytea NOT NULL,
 public_key bytea NOT NULL,
 algorithm bigint NOT NULL CHECK (algorithm IN (-8,-7,-257)),
 sign_count bigint NOT NULL CHECK (sign_count BETWEEN 0 AND 4294967295),
 transports text[] NOT NULL,
 aaguid bytea,
 backup_eligible boolean NOT NULL,
 backup_state boolean NOT NULL,
 webauthn bytea NOT NULL,
 created_at timestamptz NOT NULL,
 used_at timestamptz,
 UNIQUE (rp_id, webauthn_id),
 CHECK (NOT backup_state OR backup_eligible)
);
CREATE INDEX credential_subject ON credential(application, subject, id);
CREATE TABLE registration (
 id uuid PRIMARY KEY,
 application text NOT NULL,
 subject text NOT NULL,
 rp_id text NOT NULL,
 token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash)=32),
 webauthn bytea NOT NULL,
 state text NOT NULL CHECK (state IN ('pending','succeeded','failed','expired')),
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL CHECK (expires_at > created_at)
);
CREATE INDEX registration_subject ON registration(application, subject, created_at);
CREATE TABLE authentication (LIKE registration INCLUDING ALL);
ALTER TABLE authentication ADD COLUMN credential uuid;
CREATE TABLE history (
 id uuid PRIMARY KEY,
 application text NOT NULL,
 subject text NOT NULL,
 credential uuid,
 kind text NOT NULL,
 result text NOT NULL,
 error text,
 details jsonb NOT NULL DEFAULT '{}',
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX history_subject ON history(application, subject, occurred_at);

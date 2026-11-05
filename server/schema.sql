-- Dedicated T08-only database. Never apply to the T01/T06/T07 databases.
CREATE TABLE IF NOT EXISTS t08_users (
  id UUID PRIMARY KEY, username TEXT NOT NULL UNIQUE,
  user_handle TEXT NOT NULL UNIQUE, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS t08_passkeys (
  id TEXT PRIMARY KEY, user_id UUID NOT NULL REFERENCES t08_users(id) ON DELETE CASCADE,
  name TEXT NOT NULL, public_key BYTEA NOT NULL, counter BIGINT NOT NULL DEFAULT 0,
  transports TEXT[] NOT NULL DEFAULT '{}', device_type TEXT,
  backed_up BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS t08_passkeys_user_idx ON t08_passkeys(user_id);
CREATE TABLE IF NOT EXISTS t08_challenges (
  id UUID PRIMARY KEY, type TEXT NOT NULL CHECK (type IN ('register-new','register-add','login')),
  challenge TEXT NOT NULL, user_id UUID, username TEXT,
  display_name TEXT, user_handle TEXT, expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS t08_challenges_expire_idx ON t08_challenges(expires_at);
CREATE TABLE IF NOT EXISTS t08_sessions (
  token_hash TEXT PRIMARY KEY, user_id UUID NOT NULL REFERENCES t08_users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL, revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS t08_sessions_user_idx ON t08_sessions(user_id);
CREATE TABLE IF NOT EXISTS t08_notes (
  id UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES t08_users(id) ON DELETE CASCADE,
  title TEXT NOT NULL, body TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS t08_notes_user_idx ON t08_notes(user_id);

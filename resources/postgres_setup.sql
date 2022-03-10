CREATE EXTENSION citext;

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username CITEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    meta JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    data JSONB NOT NULL DEFAULT '{}',
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE appauth (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    token TEXT UNIQUE NOT NULL,
    meta JSONB NOT NULL DEFAULT '{}',
    expires_at TIMESTAMPTZ
);

CREATE INDEX idx_appauth__token ON appauth (token);
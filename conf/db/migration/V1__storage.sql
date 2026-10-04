-- Lattice storage (lattice.storage = "postgres").
--
-- Durable data: accounts, passkeys, identity links, Open Banking consents.
-- Shared short-lived state: login sessions, pending flows and other expiring entries, counters.
-- Expired rows are deleted by the cleanup task (lattice.postgres.cleanup-interval).

-- ------------------------------------------------------------------------------- accounts

CREATE TABLE users (
    subject          text        PRIMARY KEY,
    login_id         text,
    password_hash    text,
    claims           jsonb       NOT NULL DEFAULT '{}',
    attributes       jsonb       NOT NULL DEFAULT '{}',
    verified_claims  jsonb       NOT NULL DEFAULT '[]',
    -- Looked up case-insensitively, like the in-memory store.
    email            text        GENERATED ALWAYS AS (lower(claims ->> 'email')) STORED,
    phone_number     text        GENERATED ALWAYS AS (claims ->> 'phone_number') STORED,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX users_login_id ON users (lower(login_id));
CREATE INDEX users_email ON users (email);
CREATE INDEX users_phone_number ON users (phone_number);

-- ------------------------------------------------------------------------------- passkeys

CREATE TABLE passkeys (
    id               text        PRIMARY KEY,
    subject          text        NOT NULL,
    user_handle      text        NOT NULL,
    public_key_cose  text        NOT NULL,
    signature_count  bigint      NOT NULL,
    name             text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_used_at     timestamptz,
    backed_up        boolean     NOT NULL,
    transports       jsonb       NOT NULL DEFAULT '[]'
);

CREATE INDEX passkeys_subject ON passkeys (subject);

-- The WebAuthn user handle of each account: random, stable, never reused.
CREATE TABLE user_handles (
    subject  text PRIMARY KEY,
    handle   text NOT NULL UNIQUE
);

-- When an account was last offered to create a passkey.
CREATE TABLE passkey_offers (
    subject     text        PRIMARY KEY,
    offered_at  timestamptz NOT NULL
);

-- ------------------------------------------------------------------------------- identity links

CREATE TABLE identity_links (
    provider_id       text NOT NULL,
    external_subject  text NOT NULL,
    local_subject     text NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider_id, external_subject)
);

CREATE INDEX identity_links_local_subject ON identity_links (local_subject);

-- ------------------------------------------------------------------------------- consents

CREATE TABLE obb_consents (
    consent_id  text        PRIMARY KEY,
    consent     jsonb       NOT NULL,
    keep_until  timestamptz NOT NULL
);

CREATE INDEX obb_consents_keep_until ON obb_consents (keep_until);

-- ------------------------------------------------------------------------------- sessions

CREATE TABLE sessions (
    id            text        PRIMARY KEY,
    subject       text        NOT NULL,
    user_agent    text,
    ip            text,
    method        text,
    created_at    timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL
);

CREATE INDEX sessions_subject ON sessions (subject);
CREATE INDEX sessions_expires_at ON sessions (expires_at);
CREATE INDEX sessions_last_seen_at ON sessions (last_seen_at);

-- The apps that obtained tokens in each session (for back-channel logout).
CREATE TABLE session_clients (
    session_id         text NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    client_identifier  text NOT NULL,
    PRIMARY KEY (session_id, client_identifier)
);

-- ------------------------------------------------------------------------------- short-lived state

-- Pending sign-ins, reset links, CIBA requests, native SSO device secrets, sign-in alerts.
-- "owner" binds an entry to a browser; "subject" indexes it by account.
CREATE TABLE ephemeral (
    namespace   text        NOT NULL,
    key         text        NOT NULL,
    owner       text,
    subject     text,
    value       jsonb       NOT NULL,
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (namespace, key)
);

CREATE INDEX ephemeral_subject ON ephemeral (namespace, subject) WHERE subject IS NOT NULL;
CREATE INDEX ephemeral_expires_at ON ephemeral (expires_at);

-- Failed sign-ins, reset requests, device-code guesses, each within a window.
CREATE TABLE counters (
    key             text        PRIMARY KEY,
    count           bigint      NOT NULL,
    window_ends_at  timestamptz NOT NULL
);

CREATE INDEX counters_window_ends_at ON counters (window_ends_at);

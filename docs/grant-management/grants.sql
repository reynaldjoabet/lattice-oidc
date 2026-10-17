-- Grant Management for OAuth 2.0 (draft-ietf-oauth-v2-grant-management-03, 9 May 2023):
-- a PostgreSQL schema for an authorization server that stores grants itself.
--
-- Lattice doesn't use it: with Authlete, grants live at Authlete. It shows what the
-- specification asks an authorization server to keep, and how each operation maps onto it.
-- Section numbers (§) refer to the specification. See grant-management.md.
--
-- Run it: psql -f grants.sql (PostgreSQL 13 or newer). The examples at the end run in a
-- transaction that is rolled back, so they leave no data behind.

-- ---------------------------------------------------------------------------------- grants

-- One row per grant: the set of permissions one resource owner gave one client (§1.1).
-- Several active grants may exist for the same client and user (concurrent grants, §3.5), so
-- (client_id, subject) is deliberately not unique.
CREATE TABLE grants (
    -- §5.5: URL-safe, unique, with enough entropy that it can't be guessed. §10: public, not a
    -- secret. §9: must not identify the user, so it is random, never derived from the subject.
    grant_id           text        PRIMARY KEY CHECK (grant_id ~ '^[A-Za-z0-9_-]{22,}$'),
    client_id          text        NOT NULL,
    -- The resource owner. Never exposed through the Grant Management API (§6).
    subject            text        NOT NULL,
    -- §8.1: client IDs of one client (iOS, Android, web) may share grants, for example when
    -- registered under the same sector identifier. NULL: the grant belongs to client_id only.
    sector_identifier  text,
    -- §5.6.1: a grant becomes active once the client has claimed its tokens; an unclaimed one is
    -- deleted after a timeout (see the cleanup example). Expiry is derived from expires_at, not
    -- stored as a status, so it needs no background job to be correct.
    status             text        NOT NULL DEFAULT 'pending'
                                   CHECK (status IN ('pending', 'active', 'revoked')),
    created_at         timestamptz NOT NULL DEFAULT now(),
    last_updated_at    timestamptz NOT NULL DEFAULT now(),
    -- §6.4: who made the last change.
    updated_by         text        NOT NULL DEFAULT 'client'
                                   CHECK (updated_by IN ('client', 'authorization_server')),
    -- NULL: no expiry of its own (its components may still expire).
    expires_at         timestamptz,
    activated_at       timestamptz,
    revoked_at         timestamptz,
    CHECK ((status = 'pending') = (activated_at IS NULL AND revoked_at IS NULL)),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

-- Finding a user's grants for a client (concurrent grants, consent dashboards).
CREATE INDEX grants_client_subject ON grants (client_id, subject) WHERE status = 'active';
-- Deleting grants whose tokens were never claimed (§5.6.1).
CREATE INDEX grants_pending ON grants (created_at) WHERE status = 'pending';

-- ---------------------------------------------------------------------- grant components

-- Scopes, one row per (scope, resource) pair: RFC 8707 resource indicators can restrict a scope
-- to particular resource servers. resource = '' means the scope isn't tied to a resource.
-- Storing pairs makes "merge" a plain insert and "replace" a delete and insert; grant_resource()
-- below regroups them into the "scopes" array of §6.4.
CREATE TABLE grant_scopes (
    grant_id   text NOT NULL REFERENCES grants ON DELETE CASCADE,
    scope      text NOT NULL CHECK (scope <> '' AND scope !~ '\s'),
    resource   text NOT NULL DEFAULT '',
    PRIMARY KEY (grant_id, scope, resource)
);

-- The OpenID Connect claims the user consented to (§6.4 "claims"). The authorization server
-- decides how special scopes such as "profile" translate into claim names.
CREATE TABLE grant_claims (
    grant_id   text NOT NULL REFERENCES grants ON DELETE CASCADE,
    claim      text NOT NULL CHECK (claim <> ''),
    PRIMARY KEY (grant_id, claim)
);

-- Rich Authorization Requests (RFC 9396): each element of authorization_details as consented.
CREATE TABLE grant_authorization_details (
    grant_id    text        NOT NULL REFERENCES grants ON DELETE CASCADE,
    detail      jsonb       NOT NULL CHECK (jsonb_typeof(detail) = 'object' AND detail ? 'type'),
    type        text        GENERATED ALWAYS AS (detail ->> 'type') STORED,
    -- §8.2: an identifier inside the detail makes it addressable on its own, so a later request
    -- can change one detail instead of the whole grant. Optional; ecosystems decide.
    detail_id   text        GENERATED ALWAYS AS (detail ->> 'id') STORED,
    -- §5.6.3: details may expire individually; a grant whose details have all expired is obsolete.
    expires_at  timestamptz
);

-- No duplicates within a grant. jsonb stores objects in a canonical form (key order and spacing
-- don't matter), so its text is a stable key, as Authlete's hash comparison is.
CREATE UNIQUE INDEX grant_authorization_details_unique
    ON grant_authorization_details (grant_id, md5(detail::text));
CREATE UNIQUE INDEX grant_authorization_details_id
    ON grant_authorization_details (grant_id, detail_id) WHERE detail_id IS NOT NULL;

-- ------------------------------------------------------------------------------- tokens

-- Tokens issued under a grant, so that revoking the grant can revoke them (§6.5), and merge or
-- replace can invalidate refresh tokens (§5.2). Only a SHA-256 hash of each token is stored.
CREATE TABLE grant_tokens (
    token_hash  bytea       PRIMARY KEY CHECK (length(token_hash) = 32),
    grant_id    text        NOT NULL REFERENCES grants ON DELETE CASCADE,
    kind        text        NOT NULL CHECK (kind IN ('access', 'refresh')),
    issued_at   timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz
);

CREATE INDEX grant_tokens_live ON grant_tokens (grant_id) WHERE revoked_at IS NULL;

-- ------------------------------------------------------------------------------ history

-- What happened to each grant. §4.1: the Grant Management API is not for history (such as
-- keeping consent records for seven years), but an authorization server usually needs it for
-- audit. No foreign key, so the history outlives a deleted grant.
CREATE TABLE grant_changes (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    grant_id    text        NOT NULL,
    action      text        NOT NULL
                            CHECK (action IN ('create', 'activate', 'merge', 'replace', 'revoke', 'update', 'delete')),
    actor       text        NOT NULL CHECK (actor IN ('client', 'authorization_server', 'resource_owner')),
    changed_at  timestamptz NOT NULL DEFAULT now(),
    details     jsonb
);

CREATE INDEX grant_changes_grant ON grant_changes (grant_id, changed_at);

-- ------------------------------------------------------------------ the grant resource

-- The response to GET {grant_management_endpoint}/{grant_id} (§6.4), or NULL when the grant
-- doesn't exist, has expired or was revoked (the endpoint answers 404). It doesn't check who is
-- asking: the endpoint first verifies the access token, its grant_management_query scope, and that
-- its client owns this grant (§6.1, §6.6).
--
-- The draft names the update time both "last_updated" (in its field list) and
-- "last_updated_at" (in its example); this follows the example.
CREATE FUNCTION grant_resource(p_grant_id text) RETURNS jsonb
LANGUAGE sql STABLE AS $$
    WITH g AS (
        SELECT * FROM grants
        WHERE grant_id = p_grant_id
          AND status = 'active'
          AND (expires_at IS NULL OR expires_at > now())
    ),
    -- For each scope, the resources it was granted for; NULL when it isn't tied to one.
    per_scope AS (
        SELECT scope,
               CASE WHEN bool_or(resource = '') THEN NULL
                    ELSE array_agg(resource ORDER BY resource) END AS resources
        FROM grant_scopes WHERE grant_id = p_grant_id
        GROUP BY scope
    ),
    -- Scopes granted for the same resources form one object: {"scope": "a b", "resource": [...]}.
    clusters AS (
        SELECT string_agg(scope, ' ' ORDER BY scope) AS scope, resources
        FROM per_scope GROUP BY resources
    )
    SELECT jsonb_strip_nulls(jsonb_build_object(
        'scopes',
            (SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object('scope', scope, 'resource', to_jsonb(resources)))
                              ORDER BY resources NULLS LAST, scope)
             FROM clusters),
        'claims',
            (SELECT jsonb_agg(claim ORDER BY claim) FROM grant_claims WHERE grant_id = p_grant_id),
        'authorization_details',
            (SELECT jsonb_agg(detail ORDER BY type, detail::text)
             FROM grant_authorization_details
             WHERE grant_id = p_grant_id AND (expires_at IS NULL OR expires_at > now())),
        'created_at',      extract(epoch FROM g.created_at)::bigint,
        'last_updated_at', extract(epoch FROM g.last_updated_at)::bigint,
        'expires_at',      extract(epoch FROM g.expires_at)::bigint,
        'updated_by',      g.updated_by))
    FROM g
$$;

-- ============================================================================== examples
--
-- Each operation of the specification, on sample data. Rolled back at the end.

BEGIN;

-- create (§5.2, §5.6.1): the authorization request completes; the grant waits for its tokens.
INSERT INTO grants (grant_id, client_id, subject) VALUES ('TSdqirmAxDa0_-DB_1bASQ', 's6BhdRkqt3', 'alice');
INSERT INTO grant_scopes (grant_id, scope, resource) VALUES
    ('TSdqirmAxDa0_-DB_1bASQ', 'openid',   ''),
    ('TSdqirmAxDa0_-DB_1bASQ', 'contacts', 'https://rs.example.com/api1'),
    ('TSdqirmAxDa0_-DB_1bASQ', 'read',     'https://rs.example.com/api1');
INSERT INTO grant_claims (grant_id, claim) VALUES
    ('TSdqirmAxDa0_-DB_1bASQ', 'email'), ('TSdqirmAxDa0_-DB_1bASQ', 'given_name');
INSERT INTO grant_tokens (token_hash, grant_id, kind, expires_at) VALUES
    (sha256('2YotnFZFEjr1zCsicMWpAA'), 'TSdqirmAxDa0_-DB_1bASQ', 'access',  now() + interval '1 hour'),
    (sha256('tGzv3JOkF0XG5Qx2TlKWIA'), 'TSdqirmAxDa0_-DB_1bASQ', 'refresh', now() + interval '90 days');
INSERT INTO grant_changes (grant_id, action, actor) VALUES ('TSdqirmAxDa0_-DB_1bASQ', 'create', 'client');

-- The client redeems the code: the grant becomes active (§5.6.1).
UPDATE grants SET status = 'active', activated_at = now()
WHERE grant_id = 'TSdqirmAxDa0_-DB_1bASQ' AND status = 'pending';

-- merge (§5.2): add what the user consented to in a new request, keep the rest, and invalidate
-- the grant's existing refresh tokens. ON CONFLICT DO NOTHING makes re-granted parts no-ops.
INSERT INTO grant_scopes (grant_id, scope, resource) VALUES
    ('TSdqirmAxDa0_-DB_1bASQ', 'write', 'https://rs.example.com/api2'),
    ('TSdqirmAxDa0_-DB_1bASQ', 'write', 'https://rs.example.com/api3'),
    ('TSdqirmAxDa0_-DB_1bASQ', 'read',  'https://rs.example.com/api1')
ON CONFLICT DO NOTHING;
INSERT INTO grant_authorization_details (grant_id, detail) VALUES
    ('TSdqirmAxDa0_-DB_1bASQ',
     '{"type": "account_information", "actions": ["list_accounts", "read_balances"], "locations": ["https://example.com/accounts"]}')
ON CONFLICT DO NOTHING;
UPDATE grant_tokens SET revoked_at = now()
WHERE grant_id = 'TSdqirmAxDa0_-DB_1bASQ' AND kind = 'refresh' AND revoked_at IS NULL;
UPDATE grants SET last_updated_at = now(), updated_by = 'client' WHERE grant_id = 'TSdqirmAxDa0_-DB_1bASQ';
INSERT INTO grant_changes (grant_id, action, actor, details)
VALUES ('TSdqirmAxDa0_-DB_1bASQ', 'merge', 'client', '{"scopes": ["write"]}');

-- The same detail again, with its keys in another order: a duplicate, so nothing is added.
INSERT INTO grant_authorization_details (grant_id, detail) VALUES
    ('TSdqirmAxDa0_-DB_1bASQ',
     '{"locations": ["https://example.com/accounts"], "actions": ["list_accounts", "read_balances"], "type": "account_information"}')
ON CONFLICT DO NOTHING;

-- query (§6.4): the JSON the endpoint returns.
SELECT jsonb_pretty(grant_resource('TSdqirmAxDa0_-DB_1bASQ')) AS after_merge;

-- replace (§5.2): the grant becomes ONLY what this request consented to; refresh tokens are
-- invalidated. (§10: with self-contained access tokens, also revoke those, since the new
-- permission set need not include the old one.)
DELETE FROM grant_scopes WHERE grant_id = 'TSdqirmAxDa0_-DB_1bASQ';
DELETE FROM grant_claims WHERE grant_id = 'TSdqirmAxDa0_-DB_1bASQ';
DELETE FROM grant_authorization_details WHERE grant_id = 'TSdqirmAxDa0_-DB_1bASQ';
INSERT INTO grant_scopes (grant_id, scope, resource) VALUES
    ('TSdqirmAxDa0_-DB_1bASQ', 'openid', ''),
    ('TSdqirmAxDa0_-DB_1bASQ', 'read',   'https://rs.example.com/api1');
UPDATE grant_tokens SET revoked_at = now()
WHERE grant_id = 'TSdqirmAxDa0_-DB_1bASQ' AND kind = 'refresh' AND revoked_at IS NULL;
UPDATE grants SET last_updated_at = now(), updated_by = 'client' WHERE grant_id = 'TSdqirmAxDa0_-DB_1bASQ';
INSERT INTO grant_changes (grant_id, action, actor) VALUES ('TSdqirmAxDa0_-DB_1bASQ', 'replace', 'client');

SELECT jsonb_pretty(grant_resource('TSdqirmAxDa0_-DB_1bASQ')) AS after_replace;

-- revoke (§6.5): the grant and all its refresh tokens MUST be revoked, its access tokens SHOULD.
-- The rows stay (status 'revoked') so a stale grant_id answers 404 rather than being reusable.
UPDATE grants SET status = 'revoked', revoked_at = now(), last_updated_at = now(), updated_by = 'client'
WHERE grant_id = 'TSdqirmAxDa0_-DB_1bASQ' AND status <> 'revoked';
UPDATE grant_tokens SET revoked_at = now()
WHERE grant_id = 'TSdqirmAxDa0_-DB_1bASQ' AND revoked_at IS NULL;
INSERT INTO grant_changes (grant_id, action, actor) VALUES ('TSdqirmAxDa0_-DB_1bASQ', 'revoke', 'client');

SELECT grant_resource('TSdqirmAxDa0_-DB_1bASQ') IS NULL AS revoked_answers_404,
       (SELECT count(*) FROM grant_tokens WHERE grant_id = 'TSdqirmAxDa0_-DB_1bASQ' AND revoked_at IS NULL) AS live_tokens;

-- Cleanup (§5.6.1, §5.6.3), for a periodic job:
-- grants whose tokens were never claimed within 10 minutes;
DELETE FROM grants WHERE status = 'pending' AND created_at < now() - interval '10 minutes';
-- and active grants that are obsolete: expired, or whose authorization details have all expired.
DELETE FROM grants g
WHERE g.status = 'active'
  AND (g.expires_at < now()
       OR (EXISTS (SELECT 1 FROM grant_authorization_details d WHERE d.grant_id = g.grant_id)
           AND NOT EXISTS (SELECT 1 FROM grant_authorization_details d
                           WHERE d.grant_id = g.grant_id AND (d.expires_at IS NULL OR d.expires_at > now()))));

ROLLBACK;

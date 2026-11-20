-- Grant Management for OAuth 2.0 (draft-ietf-oauth-v2-grant-management-03, 9 May 2023):
-- a PostgreSQL schema for an authorization server that stores grants itself.
--
-- Lattice doesn't use it: with Authlete, grants live at Authlete. It shows what the
-- specification asks an authorization server to keep, and how each operation maps onto it.
-- Section numbers (§) refer to the specification. See grant-management.md.
--
-- Run it: psql -f grants.sql (PostgreSQL 19 or newer). It creates the schema "grant_management";
-- the examples at the end run in a transaction that is rolled back, so they leave no data behind.
--
-- Design:
-- * Each operation is one function call: the grant, its tokens and its history change together,
--   in one round trip, and a concurrent call on the same grant waits for the first to finish.
-- * Function bodies are SQL-standard (BEGIN ATOMIC): parsed when created, so they bind to these
--   tables whatever the caller's search_path, and the tables can't be dropped from under them.
-- * PostgreSQL 19: merge uses INSERT ... ON CONFLICT DO SELECT to tell newly granted parts from
--   ones the grant already had, in the same statement; grant IDs come from encode(..., 'base64url').
-- * PostgreSQL 18: revoke reads the previous status with RETURNING old.status; authorization
--   detail types are virtual generated columns.
-- * Every foreign key has an index on its referencing column, so deleting a grant (cascading to
--   its parts and tokens) never scans a whole table. The cleanup job deletes in batches and skips
--   rows another worker holds, so it can run on every server at once.

\set ON_ERROR_STOP on

SELECT current_setting('server_version_num')::int >= 190000 AS has_pg19 \gset
\if :has_pg19
\else
    \echo 'grants.sql needs PostgreSQL 19 or newer (INSERT ... ON CONFLICT DO SELECT).'
    \quit
\endif

BEGIN;

CREATE SCHEMA grant_management;
SET LOCAL search_path = grant_management;

-- ---------------------------------------------------------------------------------- grants

-- One row per grant: the set of permissions one resource owner gave one client (§1.1).
-- Several active grants may exist for the same client and user (concurrent grants, §3.5), so
-- (client_id, subject) is deliberately not unique.
CREATE TABLE grants (
    -- §5.5: URL-safe, unique, with enough entropy that it can't be guessed. §10: public, not a
    -- secret. §9: must not identify the user, so it is random, never derived from the subject.
    -- 16 random bytes (122 random bits) in base64url: 22 characters, no padding.
    grant_id           text        PRIMARY KEY
                                   DEFAULT encode(gen_random_uuid()::bytea, 'base64url')
                                   CHECK (grant_id ~ '^[A-Za-z0-9_-]{22,}$'),
    client_id          text        NOT NULL,
    -- The resource owner. Never exposed through the Grant Management API (§6).
    subject            text        NOT NULL,
    -- §8.1: client IDs of one client (iOS, Android, web) may share grants, for example when
    -- registered under the same sector identifier. NULL: the grant belongs to client_id only.
    sector_identifier  text,
    -- §5.6.1: a grant becomes active once the client has claimed its tokens; an unclaimed one is
    -- deleted after a timeout (grant_cleanup). Expiry is derived from expires_at, not stored as a
    -- status, so it needs no background job to be correct.
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
)
-- Merge and replace update last_updated_at, which no index covers: with free space on each page,
-- PostgreSQL rewrites the row in place (a HOT update) instead of touching every index.
WITH (fillfactor = 90);

-- Finding a user's grants for a client (concurrent grants, consent dashboards).
CREATE INDEX grants_client_subject ON grants (client_id, subject) WHERE status = 'active';
-- The cleanup job: grants whose tokens were never claimed (§5.6.1)...
CREATE INDEX grants_pending ON grants (created_at) WHERE status = 'pending';
-- ...and active grants past their own expiry.
CREATE INDEX grants_expiring ON grants (expires_at) WHERE status = 'active' AND expires_at IS NOT NULL;

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
    -- Computed when read (virtual): only used for ordering, so it isn't stored.
    type        text        GENERATED ALWAYS AS (detail ->> 'type') VIRTUAL,
    -- §8.2: an identifier inside the detail makes it addressable on its own, so a later request
    -- can change one detail instead of the whole grant. Optional; ecosystems decide. Stored,
    -- because it is indexed and PostgreSQL can't index virtual columns.
    detail_id   text        GENERATED ALWAYS AS (detail ->> 'id') STORED,
    -- §5.6.3: details may expire individually; a grant whose details have all expired is obsolete.
    expires_at  timestamptz
);

-- No duplicates within a grant. jsonb stores objects in a canonical form (key order and spacing
-- don't matter), so a hash of its text is a stable key, as Authlete's hash comparison is. The
-- hash keeps index entries small however large the detail is.
CREATE UNIQUE INDEX grant_authorization_details_unique
    ON grant_authorization_details (grant_id, sha256(detail::text::bytea));
CREATE UNIQUE INDEX grant_authorization_details_id
    ON grant_authorization_details (grant_id, detail_id) WHERE detail_id IS NOT NULL;
-- The cleanup job: details that have expired.
CREATE INDEX grant_authorization_details_expiring
    ON grant_authorization_details (expires_at) WHERE expires_at IS NOT NULL;

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
)
-- The busiest table: rows are added, revoked and deleted all day. Vacuum it at 5% dead rows
-- instead of the default 20%. pg_stat_autovacuum_scores (PostgreSQL 19) shows where it stands
-- in autovacuum's queue; REPACK (CONCURRENTLY) grant_tokens reclaims bloat without blocking.
WITH (autovacuum_vacuum_scale_factor = 0.05);

-- On every grant_id, not only live tokens: deleting a grant cascades here, and a partial index
-- couldn't find the revoked rows, so each cascade would scan the table. Revoking a token then
-- changes no indexed column, so it is a HOT update.
CREATE INDEX grant_tokens_grant ON grant_tokens (grant_id);

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
-- Append-only, so rows are on disk in time order: a BRIN index (a few pages, whatever the table's
-- size) serves time-range audits and the retention job's DELETE ... WHERE changed_at < ...
CREATE INDEX grant_changes_time ON grant_changes USING brin (changed_at);

-- --------------------------------------------------------------------- the grant resource

-- (scope, resource) rows from the "scopes" array of a request or response (§6.4):
-- [{"scope": "read write", "resource": ["https://rs.example.com/api1"]}, {"scope": "openid"}].
CREATE FUNCTION scope_rows(p_scopes jsonb) RETURNS TABLE (scope text, resource text)
LANGUAGE sql IMMUTABLE PARALLEL SAFE
BEGIN ATOMIC
    SELECT DISTINCT s.scope, coalesce(r.resource, '')
    FROM jsonb_array_elements(p_scopes) AS e
    CROSS JOIN LATERAL string_to_table(e ->> 'scope', ' ') AS s(scope)
    LEFT JOIN LATERAL jsonb_array_elements_text(e -> 'resource') AS r(resource) ON true
    WHERE s.scope <> '';
END;

-- The response to GET {grant_management_endpoint}/{grant_id} (§6.4), or NULL when the grant
-- doesn't exist, has expired or was revoked (the endpoint answers 404). It doesn't check who is
-- asking: the endpoint first verifies the access token, its grant_management_query scope, and that
-- its client owns this grant (§6.1, §6.6).
--
-- The draft names the update time both "last_updated" (in its field list) and
-- "last_updated_at" (in its example); this follows the example.
CREATE FUNCTION grant_resource(p_grant_id text) RETURNS jsonb
LANGUAGE sql STABLE PARALLEL SAFE
BEGIN ATOMIC
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
    FROM g;
END;

-- ------------------------------------------------------------------------------ operations

-- create (§5.2, §5.6.1): the authorization request completes; the grant waits for its tokens.
-- Returns the new grant_id. The parts use the shapes of §6.4.
CREATE FUNCTION grant_create(
    p_client_id   text,
    p_subject     text,
    p_scopes      jsonb       DEFAULT '[]',
    p_claims      text[]      DEFAULT '{}',
    p_details     jsonb       DEFAULT '[]',
    p_expires_at  timestamptz DEFAULT NULL
) RETURNS text
LANGUAGE sql
BEGIN ATOMIC
    WITH g AS (
        INSERT INTO grants (client_id, subject, expires_at)
        VALUES (p_client_id, p_subject, p_expires_at)
        RETURNING grant_id
    ),
    s AS (
        INSERT INTO grant_scopes (grant_id, scope, resource)
        SELECT g.grant_id, x.scope, x.resource FROM g, scope_rows(p_scopes) AS x
    ),
    c AS (
        INSERT INTO grant_claims (grant_id, claim)
        SELECT DISTINCT g.grant_id, x.claim FROM g, unnest(p_claims) AS x(claim)
    ),
    d AS (
        INSERT INTO grant_authorization_details (grant_id, detail)
        SELECT g.grant_id, x.detail FROM g, jsonb_array_elements(p_details) AS x(detail)
        ON CONFLICT DO NOTHING
    ),
    h AS (
        INSERT INTO grant_changes (grant_id, action, actor)
        SELECT grant_id, 'create', 'client' FROM g
    )
    SELECT grant_id FROM g;
END;

-- The client redeems the code: the grant becomes active (§5.6.1). False if it wasn't pending.
CREATE FUNCTION grant_activate(p_grant_id text) RETURNS boolean
LANGUAGE sql
BEGIN ATOMIC
    WITH g AS (
        UPDATE grants SET status = 'active', activated_at = now()
        WHERE grant_id = p_grant_id AND status = 'pending'
        RETURNING grant_id
    ),
    h AS (
        INSERT INTO grant_changes (grant_id, action, actor)
        SELECT grant_id, 'activate', 'client' FROM g
    )
    SELECT EXISTS (SELECT FROM g);
END;

-- merge (§5.2): add what the user consented to in a new request, keep the rest, and invalidate
-- the grant's refresh tokens. Returns what was newly added and what the grant already had, or
-- NULL when the grant isn't active.
--
-- ON CONFLICT DO SELECT (PostgreSQL 19) returns the existing row on a conflict, with "old" set to
-- it; for a new row "old" is NULL. So one statement adds the new parts and reports both kinds,
-- and the history records only what really changed. Updating the grant row first locks it: a
-- concurrent merge, replace or revoke of the same grant waits.
CREATE FUNCTION grant_merge(
    p_grant_id  text,
    p_scopes    jsonb  DEFAULT '[]',
    p_claims    text[] DEFAULT '{}',
    p_details   jsonb  DEFAULT '[]'
) RETURNS jsonb
LANGUAGE sql
BEGIN ATOMIC
    WITH g AS (
        UPDATE grants SET last_updated_at = now(), updated_by = 'client'
        WHERE grant_id = p_grant_id
          AND status = 'active'
          AND (expires_at IS NULL OR expires_at > now())
        RETURNING grant_id
    ),
    s AS (
        INSERT INTO grant_scopes (grant_id, scope, resource)
        SELECT g.grant_id, x.scope, x.resource FROM g, scope_rows(p_scopes) AS x
        ON CONFLICT (grant_id, scope, resource) DO SELECT
        RETURNING scope, resource, old IS NULL AS added
    ),
    c AS (
        INSERT INTO grant_claims (grant_id, claim)
        SELECT DISTINCT g.grant_id, x.claim FROM g, unnest(p_claims) AS x(claim)
        ON CONFLICT (grant_id, claim) DO SELECT
        RETURNING claim, old IS NULL AS added
    ),
    d AS (
        INSERT INTO grant_authorization_details (grant_id, detail)
        SELECT DISTINCT g.grant_id, x.detail FROM g, jsonb_array_elements(p_details) AS x(detail)
        ON CONFLICT (grant_id, sha256(detail::text::bytea)) DO SELECT
        RETURNING detail, old IS NULL AS added
    ),
    t AS (
        UPDATE grant_tokens SET revoked_at = now()
        WHERE grant_id IN (SELECT grant_id FROM g) AND kind = 'refresh' AND revoked_at IS NULL
        RETURNING token_hash
    ),
    result AS (
        SELECT jsonb_strip_nulls(jsonb_build_object(
            'added', jsonb_strip_nulls(jsonb_build_object(
                'scopes',  (SELECT jsonb_agg(jsonb_build_object('scope', scope, 'resource', nullif(resource, ''))
                                             ORDER BY scope, resource) FROM s WHERE added),
                'claims',  (SELECT jsonb_agg(claim ORDER BY claim) FROM c WHERE added),
                'authorization_details', (SELECT jsonb_agg(detail) FROM d WHERE added))),
            'already_granted', jsonb_strip_nulls(jsonb_build_object(
                'scopes',  (SELECT jsonb_agg(jsonb_build_object('scope', scope, 'resource', nullif(resource, ''))
                                             ORDER BY scope, resource) FROM s WHERE NOT added),
                'claims',  (SELECT jsonb_agg(claim ORDER BY claim) FROM c WHERE NOT added),
                'authorization_details', (SELECT jsonb_agg(detail) FROM d WHERE NOT added))),
            'refresh_tokens_revoked', (SELECT count(*) FROM t))) AS summary
    ),
    h AS (
        INSERT INTO grant_changes (grant_id, action, actor, details)
        SELECT g.grant_id, 'merge', 'client', result.summary -> 'added' FROM g, result
        WHERE result.summary -> 'added' <> '{}'  -- nothing new: nothing to record
    )
    SELECT result.summary FROM g, result;
END;

-- replace (§5.2): the grant becomes ONLY what this request consented to; refresh tokens are
-- invalidated. (§10: with self-contained access tokens, also revoke those, since the new
-- permission set need not include the old one.) False when the grant isn't active.
--
-- PL/pgSQL rather than one SQL statement: the old parts must be gone before the new ones are
-- inserted, and parts of one statement can't see each other's changes.
CREATE FUNCTION grant_replace(
    p_grant_id  text,
    p_scopes    jsonb  DEFAULT '[]',
    p_claims    text[] DEFAULT '{}',
    p_details   jsonb  DEFAULT '[]'
) RETURNS boolean
LANGUAGE plpgsql
SET search_path = grant_management, pg_temp
AS $$
BEGIN
    -- Locks the grant row: a concurrent merge, replace or revoke of this grant waits.
    UPDATE grants SET last_updated_at = now(), updated_by = 'client'
    WHERE grant_id = p_grant_id AND status = 'active' AND (expires_at IS NULL OR expires_at > now());
    IF NOT FOUND THEN
        RETURN false;
    END IF;

    DELETE FROM grant_scopes WHERE grant_id = p_grant_id;
    DELETE FROM grant_claims WHERE grant_id = p_grant_id;
    DELETE FROM grant_authorization_details WHERE grant_id = p_grant_id;

    INSERT INTO grant_scopes (grant_id, scope, resource)
    SELECT p_grant_id, x.scope, x.resource FROM scope_rows(p_scopes) AS x;
    INSERT INTO grant_claims (grant_id, claim)
    SELECT DISTINCT p_grant_id, x.claim FROM unnest(p_claims) AS x(claim);
    INSERT INTO grant_authorization_details (grant_id, detail)
    SELECT p_grant_id, x.detail FROM jsonb_array_elements(p_details) AS x(detail)
    ON CONFLICT DO NOTHING;

    UPDATE grant_tokens SET revoked_at = now()
    WHERE grant_id = p_grant_id AND kind = 'refresh' AND revoked_at IS NULL;

    INSERT INTO grant_changes (grant_id, action, actor, details)
    VALUES (p_grant_id, 'replace', 'client',
            jsonb_build_object('scopes', p_scopes, 'claims', to_jsonb(p_claims), 'authorization_details', p_details));
    RETURN true;
END
$$;

-- revoke (§6.5): the grant and all its refresh tokens MUST be revoked, its access tokens SHOULD.
-- The rows stay (status 'revoked') so a stale grant_id answers 404 rather than being reusable.
-- p_actor: 'client' through the API, 'resource_owner' from a consent dashboard, or
-- 'authorization_server'. False if the grant doesn't exist or was already revoked.
CREATE FUNCTION grant_revoke(p_grant_id text, p_actor text DEFAULT 'client') RETURNS boolean
LANGUAGE sql
BEGIN ATOMIC
    WITH g AS (
        UPDATE grants
        SET status = 'revoked', revoked_at = now(), last_updated_at = now(),
            updated_by = CASE p_actor WHEN 'client' THEN 'client' ELSE 'authorization_server' END
        WHERE grant_id = p_grant_id AND status <> 'revoked'
        -- PostgreSQL 18: the status before this update, for the history.
        RETURNING grant_id, old.status AS previous_status
    ),
    t AS (
        UPDATE grant_tokens SET revoked_at = now()
        WHERE grant_id IN (SELECT grant_id FROM g) AND revoked_at IS NULL
        RETURNING kind
    ),
    h AS (
        INSERT INTO grant_changes (grant_id, action, actor, details)
        SELECT grant_id, 'revoke', p_actor,
               jsonb_build_object('previous_status', previous_status,
                                  'tokens_revoked',  (SELECT count(*) FROM t))
        FROM g
    )
    SELECT EXISTS (SELECT FROM g);
END;

-- Cleanup (§5.6.1, §5.6.3), for a periodic job: deletes up to p_batch obsolete grants and returns
-- how many it deleted; run it again while it returns p_batch. Obsolete means: never claimed within
-- p_pending_timeout, past its own expiry, or all of its authorization details have expired.
--
-- Each kind is found through its own index (an OR across them would scan the table), and
-- FOR UPDATE SKIP LOCKED lets several servers run the job at once, each taking different grants.
-- Batches keep each transaction short, so a large backlog doesn't hold locks or bloat the tables.
CREATE FUNCTION grant_cleanup(p_pending_timeout interval DEFAULT '10 minutes', p_batch int DEFAULT 1000)
RETURNS bigint
LANGUAGE sql
BEGIN ATOMIC
    WITH candidates AS (
        SELECT grant_id FROM grants
        WHERE status = 'pending' AND created_at < now() - p_pending_timeout
        UNION
        SELECT grant_id FROM grants
        WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= now()
        UNION
        -- Grants with an expired detail and no live one left.
        SELECT d.grant_id FROM grant_authorization_details AS d
        WHERE d.expires_at IS NOT NULL AND d.expires_at <= now()
          AND NOT EXISTS (SELECT FROM grant_authorization_details AS live
                          WHERE live.grant_id = d.grant_id
                            AND (live.expires_at IS NULL OR live.expires_at > now()))
    ),
    batch AS (
        SELECT g.grant_id FROM grants AS g
        WHERE g.grant_id IN (SELECT grant_id FROM candidates) AND g.status <> 'revoked'
        LIMIT p_batch
        FOR UPDATE SKIP LOCKED
    ),
    deleted AS (
        DELETE FROM grants WHERE grant_id IN (SELECT grant_id FROM batch)
        RETURNING grant_id, status
    ),
    h AS (
        INSERT INTO grant_changes (grant_id, action, actor, details)
        SELECT grant_id, 'delete', 'authorization_server', jsonb_build_object('status', status)
        FROM deleted
    )
    SELECT count(*) FROM deleted;
END;

COMMIT;

-- ============================================================================== examples
--
-- Each operation of the specification, on sample data. Rolled back at the end.

BEGIN;
SET LOCAL search_path = grant_management;

-- create: Alice gives the client "s6BhdRkqt3" three scopes and two claims.
SELECT grant_create(
           's6BhdRkqt3', 'alice',
           p_scopes => '[{"scope": "openid"},
                         {"scope": "contacts read", "resource": ["https://rs.example.com/api1"]}]',
           p_claims => '{email,given_name}') AS grant_id \gset

-- Its tokens, stored as hashes.
INSERT INTO grant_tokens (token_hash, grant_id, kind, expires_at) VALUES
    (sha256('2YotnFZFEjr1zCsicMWpAA'), :'grant_id', 'access',  now() + interval '1 hour'),
    (sha256('tGzv3JOkF0XG5Qx2TlKWIA'), :'grant_id', 'refresh', now() + interval '90 days');

-- The client redeems the code: the grant becomes active.
SELECT grant_activate(:'grant_id') AS activated;

-- merge: "read" on api1 was already granted, "write" is new, and so is the authorization detail.
SELECT jsonb_pretty(grant_merge(
           :'grant_id',
           p_scopes  => '[{"scope": "write", "resource": ["https://rs.example.com/api2", "https://rs.example.com/api3"]},
                          {"scope": "read",  "resource": ["https://rs.example.com/api1"]}]',
           p_details => '[{"type": "account_information", "actions": ["list_accounts", "read_balances"],
                           "locations": ["https://example.com/accounts"]}]')) AS merge_result;

-- The same detail again, with its keys in another order: already granted, nothing added.
SELECT grant_merge(
           :'grant_id',
           p_details => '[{"locations": ["https://example.com/accounts"], "type": "account_information",
                           "actions": ["list_accounts", "read_balances"]}]') -> 'already_granted' AS duplicate_detail;

-- query (§6.4): the JSON the endpoint returns.
SELECT jsonb_pretty(grant_resource(:'grant_id')) AS after_merge;

-- replace: the grant becomes only "openid" and "read" on api1.
SELECT grant_replace(
           :'grant_id',
           p_scopes => '[{"scope": "openid"}, {"scope": "read", "resource": ["https://rs.example.com/api1"]}]') AS replaced;

SELECT jsonb_pretty(grant_resource(:'grant_id')) AS after_replace;

-- revoke, from Alice's consent dashboard: the grant answers 404 and no token is live.
SELECT grant_revoke(:'grant_id', 'resource_owner') AS revoked,
       grant_revoke(:'grant_id', 'resource_owner') AS revoked_again;

SELECT grant_resource(:'grant_id') IS NULL AS revoked_answers_404,
       (SELECT count(*) FROM grant_tokens WHERE grant_id = :'grant_id' AND revoked_at IS NULL) AS live_tokens;

-- The history of this grant.
SELECT action, actor, details FROM grant_changes WHERE grant_id = :'grant_id' ORDER BY id;

-- cleanup: a grant whose tokens were never claimed, created 20 minutes ago.
INSERT INTO grants (client_id, subject, created_at) VALUES ('s6BhdRkqt3', 'bob', now() - interval '20 minutes');
SELECT grant_cleanup() AS deleted_grants;

ROLLBACK;

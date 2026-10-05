-- Second factors: authenticator apps (secret encrypted with AES-GCM) and single-use recovery codes
-- (stored as keyed hashes).
CREATE TABLE totp_credentials (
    subject         text        PRIMARY KEY,
    secret          text        NOT NULL,
    created_at      timestamptz NOT NULL,
    -- The last 30-second time step a code was accepted for; older or equal steps are refused.
    last_used_step  bigint      NOT NULL DEFAULT 0
);

CREATE TABLE recovery_codes (
    subject    text NOT NULL,
    code_hash  text NOT NULL,
    PRIMARY KEY (subject, code_hash)
);

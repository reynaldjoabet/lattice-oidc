-- What each account approved for each app on the consent page. A request asking for nothing more
-- is issued without showing the page again.
CREATE TABLE app_consents (
    subject     text        NOT NULL,
    client_id   bigint      NOT NULL,
    -- Space-separated, as in OAuth.
    scopes      text        NOT NULL,
    claims      text        NOT NULL,
    granted_at  timestamptz NOT NULL,
    PRIMARY KEY (subject, client_id)
);

CREATE INDEX app_consents_client ON app_consents (client_id);

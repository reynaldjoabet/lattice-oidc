-- The stored audit trail (operator console audit log). Kept for lattice.audit.retention.
CREATE TABLE audit_events (
    id           bigserial   PRIMARY KEY,
    occurred_at  timestamptz NOT NULL,
    event        text        NOT NULL,
    subject      text,
    record       jsonb       NOT NULL
);

CREATE INDEX audit_events_occurred_at ON audit_events (occurred_at);
CREATE INDEX audit_events_event ON audit_events (event, id);
CREATE INDEX audit_events_subject ON audit_events (subject, id) WHERE subject IS NOT NULL;

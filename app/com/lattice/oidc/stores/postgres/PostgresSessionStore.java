package com.lattice.oidc.stores.postgres;

import com.lattice.oidc.stores.SessionStore;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/** {@link SessionStore} in PostgreSQL (tables {@code sessions} and {@code session_clients}). */
@Singleton
public final class PostgresSessionStore implements SessionStore {

  private static final String COLUMNS =
      "id, subject, user_agent, ip, method, created_at, last_seen_at, expires_at, remember_me";

  private final PostgresDatabase database;

  @Inject
  public PostgresSessionStore(PostgresDatabase database) {
    this.database = database;
  }

  private static Session session(ResultSet row) throws SQLException {
    return new Session(
        row.getString("id"),
        row.getString("subject"),
        row.getString("user_agent"),
        row.getString("ip"),
        row.getString("method"),
        PostgresDatabase.instant(row, "created_at"),
        PostgresDatabase.instant(row, "last_seen_at"),
        PostgresDatabase.instant(row, "expires_at"),
        row.getBoolean("remember_me"));
  }

  @Override
  public void create(Session session) {
    database.update(
        "INSERT INTO sessions (" + COLUMNS + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        session.id(),
        session.subject(),
        session.userAgent(),
        session.ip(),
        session.method(),
        session.createdAt(),
        session.lastSeenAt(),
        session.expiresAt(),
        session.rememberMe());
  }

  @Override
  public Optional<Session> find(String id) {
    if (id == null) {
      return Optional.empty();
    }
    return database.queryOne(
        "SELECT " + COLUMNS + " FROM sessions WHERE id = ? AND expires_at > ?",
        PostgresSessionStore::session,
        id, Instant.now());
  }

  @Override
  public void touch(String id, Instant now, Duration interval) {
    // Writes only when the last recorded activity is older than the interval.
    database.update(
        "UPDATE sessions SET last_seen_at = ? WHERE id = ? AND last_seen_at < ?",
        now, id, now.minus(interval));
  }

  @Override
  public Optional<Session> end(String id) {
    if (id == null) {
      return Optional.empty();
    }
    // session_clients rows go with it (ON DELETE CASCADE).
    return database.queryOne(
        "DELETE FROM sessions WHERE id = ? RETURNING " + COLUMNS, PostgresSessionStore::session, id);
  }

  @Override
  public List<Session> forSubject(String subject) {
    return database.query(
        "SELECT " + COLUMNS + " FROM sessions WHERE subject = ? AND expires_at > ? ORDER BY last_seen_at DESC",
        PostgresSessionStore::session,
        subject, Instant.now());
  }

  @Override
  public void addClient(String id, String clientIdentifier) {
    // Only for a session that still exists; a repeated client is ignored.
    database.update(
        """
        INSERT INTO session_clients (session_id, client_identifier)
        SELECT id, ? FROM sessions WHERE id = ?
        ON CONFLICT DO NOTHING
        """,
        clientIdentifier, id);
  }

  @Override
  public Set<String> clients(String id) {
    return new LinkedHashSet<>(
        database.query(
            "SELECT client_identifier FROM session_clients WHERE session_id = ? ORDER BY client_identifier",
            row -> row.getString(1),
            id));
  }

  @Override
  public long countActive() {
    return database
        .queryOne("SELECT count(*) FROM sessions WHERE expires_at > ?", row -> row.getLong(1), Instant.now())
        .orElse(0L);
  }
}

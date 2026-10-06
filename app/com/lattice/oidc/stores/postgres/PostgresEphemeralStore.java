package com.lattice.oidc.stores.postgres;

import com.lattice.oidc.stores.EphemeralStore;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/** {@link EphemeralStore} in PostgreSQL (table {@code ephemeral}). Expiry uses the database clock. */
@Singleton
public final class PostgresEphemeralStore implements EphemeralStore {

  private static final String COLUMNS = "namespace, key, owner, subject, value::text AS value, expires_at";

  private final PostgresDatabase database;

  @Inject
  public PostgresEphemeralStore(PostgresDatabase database) {
    this.database = database;
  }

  private static Entry entry(ResultSet row) throws SQLException {
    return new Entry(
        row.getString("namespace"),
        row.getString("key"),
        row.getString("owner"),
        row.getString("subject"),
        row.getString("value"),
        PostgresDatabase.instant(row, "expires_at"));
  }

  @Override
  public void put(String namespace, String key, String owner, String subject, String json, Duration ttl) {
    database.update(
        """
        INSERT INTO ephemeral (namespace, key, owner, subject, value, expires_at)
        VALUES (?, ?, ?, ?, ?::jsonb, now() + make_interval(secs => ?))
        ON CONFLICT (namespace, key) DO UPDATE
          SET owner = EXCLUDED.owner, subject = EXCLUDED.subject, value = EXCLUDED.value,
              expires_at = EXCLUDED.expires_at
        """,
        namespace, key, owner, subject, json, ttl);
  }

  @Override
  public Optional<Entry> get(String namespace, String key) {
    return database.queryOne(
        "SELECT " + COLUMNS + " FROM ephemeral WHERE namespace = ? AND key = ? AND expires_at > now()",
        PostgresEphemeralStore::entry,
        namespace, key);
  }

  @Override
  public Optional<Entry> take(String namespace, String key) {
    // One statement: of two concurrent callers, only one deletes (and so receives) the row.
    return database.queryOne(
        "DELETE FROM ephemeral WHERE namespace = ? AND key = ? AND expires_at > now() RETURNING " + COLUMNS,
        PostgresEphemeralStore::entry,
        namespace, key);
  }

  @Override
  public List<Entry> bySubject(String namespace, String subject) {
    return database.query(
        "SELECT " + COLUMNS
            + " FROM ephemeral WHERE namespace = ? AND subject = ? AND expires_at > now() ORDER BY expires_at",
        PostgresEphemeralStore::entry,
        namespace, subject);
  }

  @Override
  public void delete(String namespace, String key) {
    database.update("DELETE FROM ephemeral WHERE namespace = ? AND key = ?", namespace, key);
  }

  @Override
  public int deleteBySubject(String namespace, String subject) {
    return database.update("DELETE FROM ephemeral WHERE namespace = ? AND subject = ?", namespace, subject);
  }

  @Override
  public long count(String namespace) {
    return database
        .queryOne(
            "SELECT count(*) FROM ephemeral WHERE namespace = ? AND expires_at > now()",
            row -> row.getLong(1),
            namespace)
        .orElse(0L);
  }

  @Override
  public Map<String, Long> counts() {
    Map<String, Long> counts = new TreeMap<>();
    database.query(
        "SELECT namespace, count(*) AS entries FROM ephemeral WHERE expires_at > now() GROUP BY namespace",
        row -> counts.put(row.getString("namespace"), row.getLong("entries")));
    return counts;
  }
}

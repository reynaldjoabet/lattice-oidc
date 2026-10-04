package com.lattice.oidc.stores.postgres;

import com.lattice.oidc.stores.CounterStore;
import java.time.Duration;
import javax.inject.Inject;
import javax.inject.Singleton;

/** {@link CounterStore} in PostgreSQL (table {@code counters}). Windows use the database clock. */
@Singleton
public final class PostgresCounterStore implements CounterStore {

  private final PostgresDatabase database;

  @Inject
  public PostgresCounterStore(PostgresDatabase database) {
    this.database = database;
  }

  @Override
  public long increment(String key, Duration window) {
    // One statement: concurrent increments on any server all count. An ended window starts over.
    return database
        .queryOne(
            """
            INSERT INTO counters (key, count, window_ends_at)
            VALUES (?, 1, now() + make_interval(secs => ?))
            ON CONFLICT (key) DO UPDATE SET
              count = CASE WHEN counters.window_ends_at > now() THEN counters.count + 1 ELSE 1 END,
              window_ends_at = CASE WHEN counters.window_ends_at > now()
                                    THEN counters.window_ends_at ELSE EXCLUDED.window_ends_at END
            RETURNING count
            """,
            row -> row.getLong(1),
            key, window)
        .orElseThrow();
  }

  @Override
  public long count(String key) {
    return database
        .queryOne(
            "SELECT count FROM counters WHERE key = ? AND window_ends_at > now()", row -> row.getLong(1), key)
        .orElse(0L);
  }

  @Override
  public void reset(String key) {
    database.update("DELETE FROM counters WHERE key = ?", key);
  }

  @Override
  public void resetPrefix(String prefix) {
    database.update("DELETE FROM counters WHERE starts_with(key, ?)", prefix);
  }

  @Override
  public long countAtLeast(String prefix, long minimum) {
    return database
        .queryOne(
            "SELECT count(*) FROM counters WHERE starts_with(key, ?) AND count >= ? AND window_ends_at > now()",
            row -> row.getLong(1),
            prefix, minimum)
        .orElse(0L);
  }
}

package com.lattice.oidc.stores.jpa;

import com.lattice.oidc.stores.CounterStore;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.time.Duration;

/**
 * {@link CounterStore} through JPA (entity {@link CounterEntity}, table {@code counters}). Windows use
 * the database clock.
 */
@Singleton
public final class JpaCounterStore implements CounterStore {

  private final JpaDatabase database;

  @Inject
  public JpaCounterStore(JpaDatabase database) {
    this.database = database;
  }

  @Override
  public long increment(String key, Duration window) {
    // Native SQL: one statement, so concurrent increments on any server all count. An ended window
    // starts over. JPQL has no upsert, and a read-then-write would lose concurrent increments.
    return database.transaction(
        em ->
            ((Number)
                    em.createNativeQuery(
                            """
                            INSERT INTO counters (key, count, window_ends_at)
                            VALUES (?1, 1, now() + make_interval(secs => ?2))
                            ON CONFLICT (key) DO UPDATE SET
                              count = CASE WHEN counters.window_ends_at > now() THEN counters.count + 1 ELSE 1 END,
                              window_ends_at = CASE WHEN counters.window_ends_at > now()
                                                    THEN counters.window_ends_at ELSE EXCLUDED.window_ends_at END
                            RETURNING count
                            """)
                        .setParameter(1, key)
                        .setParameter(2, JpaDatabase.seconds(window))
                        .getSingleResult())
                .longValue());
  }

  @Override
  public long count(String key) {
    return database.transaction(
        em ->
            em.createQuery(
                    "select c.hits from CounterEntity c where c.counterKey = :key and c.windowEndsAt > instant", Long.class)
                .setParameter("key", key)
                .getResultStream()
                .findFirst()
                .orElse(0L));
  }

  @Override
  public void reset(String key) {
    database.transaction(
        em -> em.createQuery("delete from CounterEntity c where c.counterKey = :key").setParameter("key", key).executeUpdate());
  }

  @Override
  public void resetPrefix(String prefix) {
    // Native SQL: starts_with compares the prefix literally, without LIKE's wildcards.
    database.transaction(
        em -> em.createNativeQuery("DELETE FROM counters WHERE starts_with(key, ?1)").setParameter(1, prefix).executeUpdate());
  }

  @Override
  public long countAtLeast(String prefix, long minimum) {
    return database.transaction(
        em ->
            ((Number)
                    em.createNativeQuery(
                            "SELECT count(*) FROM counters WHERE starts_with(key, ?1) AND count >= ?2 AND window_ends_at > now()")
                        .setParameter(1, prefix)
                        .setParameter(2, minimum)
                        .getSingleResult())
                .longValue());
  }
}

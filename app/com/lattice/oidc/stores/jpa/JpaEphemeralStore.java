package com.lattice.oidc.stores.jpa;

import com.lattice.oidc.stores.EphemeralStore;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * {@link EphemeralStore} through JPA (entity {@link EphemeralEntity}, table {@code ephemeral}).
 * Expiry uses the database clock: {@code now()} in SQL, {@code instant} in JPQL.
 */
@Singleton
public final class JpaEphemeralStore implements EphemeralStore {

  private final JpaDatabase database;

  @Inject
  public JpaEphemeralStore(JpaDatabase database) {
    this.database = database;
  }

  private static Entry entry(EphemeralEntity e) {
    return new Entry(e.namespace, e.entryKey, e.owner, e.subject, e.json, e.expiresAt);
  }

  @Override
  public void put(String namespace, String key, String owner, String subject, String json, Duration ttl) {
    // Native SQL: an atomic upsert, with the expiry computed from the database clock.
    database.transaction(
        em ->
            em.createNativeQuery(
                    """
                    INSERT INTO ephemeral (namespace, key, owner, subject, value, expires_at)
                    VALUES (?1, ?2, ?3, ?4, CAST(?5 AS jsonb), now() + make_interval(secs => ?6))
                    ON CONFLICT (namespace, key) DO UPDATE
                      SET owner = EXCLUDED.owner, subject = EXCLUDED.subject, value = EXCLUDED.value,
                          expires_at = EXCLUDED.expires_at
                    """)
                .setParameter(1, namespace)
                .setParameter(2, key)
                .setParameter(3, owner)
                .setParameter(4, subject)
                .setParameter(5, json)
                .setParameter(6, JpaDatabase.seconds(ttl))
                .executeUpdate());
  }

  @Override
  public Optional<Entry> get(String namespace, String key) {
    return database.transaction(
        em ->
            em.createQuery(
                    "select e from EphemeralEntity e where e.namespace = :namespace and e.entryKey = :key and e.expiresAt > instant",
                    EphemeralEntity.class)
                .setParameter("namespace", namespace)
                .setParameter("key", key)
                .getResultStream()
                .findFirst()
                .map(JpaEphemeralStore::entry));
  }

  @Override
  public Optional<Entry> take(String namespace, String key) {
    // Native SQL: one statement, so of two concurrent callers only one deletes (and so receives) the
    // row. A JPA find-then-remove would let both read it first.
    return database.transaction(
        em ->
            JpaDatabase.<EphemeralEntity>resultList(
                    em.createNativeQuery(
                            """
                            DELETE FROM ephemeral WHERE namespace = ?1 AND key = ?2 AND expires_at > now()
                            RETURNING namespace, key, owner, subject, value, expires_at
                            """,
                            EphemeralEntity.class)
                        .setParameter(1, namespace)
                        .setParameter(2, key))
                .stream()
                .findFirst()
                .map(JpaEphemeralStore::entry));
  }

  @Override
  public List<Entry> bySubject(String namespace, String subject) {
    return database.transaction(
        em ->
            em.createQuery(
                    """
                    select e from EphemeralEntity e
                    where e.namespace = :namespace and e.subject = :subject and e.expiresAt > instant
                    order by e.expiresAt
                    """,
                    EphemeralEntity.class)
                .setParameter("namespace", namespace)
                .setParameter("subject", subject)
                .getResultStream()
                .map(JpaEphemeralStore::entry)
                .toList());
  }

  @Override
  public void delete(String namespace, String key) {
    database.transaction(
        em ->
            em.createQuery("delete from EphemeralEntity e where e.namespace = :namespace and e.entryKey = :key")
                .setParameter("namespace", namespace)
                .setParameter("key", key)
                .executeUpdate());
  }

  @Override
  public int deleteBySubject(String namespace, String subject) {
    return database.transaction(
        em ->
            em.createQuery("delete from EphemeralEntity e where e.namespace = :namespace and e.subject = :subject")
                .setParameter("namespace", namespace)
                .setParameter("subject", subject)
                .executeUpdate());
  }

  @Override
  public long count(String namespace) {
    return database.transaction(
        em ->
            em.createQuery(
                    "select count(e) from EphemeralEntity e where e.namespace = :namespace and e.expiresAt > instant", Long.class)
                .setParameter("namespace", namespace)
                .getSingleResult());
  }

  @Override
  public Map<String, Long> counts() {
    return database.transaction(
        em -> {
          Map<String, Long> counts = new TreeMap<>();
          em.createQuery(
                  "select e.namespace, count(e) from EphemeralEntity e where e.expiresAt > instant group by e.namespace",
                  Object[].class)
              .getResultStream()
              .forEach(row -> counts.put((String) row[0], (Long) row[1]));
          return counts;
        });
  }
}

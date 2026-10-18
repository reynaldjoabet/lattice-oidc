package com.lattice.oidc.stores.jpa;

import com.lattice.oidc.stores.SessionStore;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * {@link SessionStore} through JPA (entities {@link SessionEntity} and {@link SessionClientEntity},
 * tables {@code sessions} and {@code session_clients}).
 */
@Singleton
public final class JpaSessionStore implements SessionStore {

  private final JpaDatabase database;

  @Inject
  public JpaSessionStore(JpaDatabase database) {
    this.database = database;
  }

  private static Session session(SessionEntity s) {
    return new Session(s.id, s.subject, s.userAgent, s.ip, s.method, s.createdAt, s.lastSeenAt, s.expiresAt, s.rememberMe);
  }

  @Override
  public void create(Session session) {
    database.transaction(
        em -> {
          em.persist(
              new SessionEntity(
                  session.id(),
                  session.subject(),
                  session.userAgent(),
                  session.ip(),
                  session.method(),
                  session.createdAt(),
                  session.lastSeenAt(),
                  session.expiresAt(),
                  session.rememberMe()));
          return null;
        });
  }

  @Override
  public Optional<Session> find(String id) {
    if (id == null) {
      return Optional.empty();
    }
    return database.transaction(
        em ->
            em.createQuery("select s from SessionEntity s where s.id = :id and s.expiresAt > :now", SessionEntity.class)
                .setParameter("id", id)
                .setParameter("now", Instant.now())
                .getResultStream()
                .findFirst()
                .map(JpaSessionStore::session));
  }

  @Override
  public void touch(String id, Instant now, Duration interval) {
    // One bulk update: writes only when the last recorded activity is older than the interval.
    database.transaction(
        em ->
            em.createQuery("update SessionEntity s set s.lastSeenAt = :now where s.id = :id and s.lastSeenAt < :since")
                .setParameter("now", now)
                .setParameter("id", id)
                .setParameter("since", now.minus(interval))
                .executeUpdate());
  }

  @Override
  public Optional<Session> end(String id) {
    if (id == null) {
      return Optional.empty();
    }
    // Native SQL: delete and return in one statement, so of two concurrent logouts only one gets the
    // session. session_clients rows go with it (ON DELETE CASCADE).
    return database.transaction(
        em ->
            JpaDatabase.<SessionEntity>resultList(
                    em.createNativeQuery(
                            """
                            DELETE FROM sessions WHERE id = ?1
                            RETURNING id, subject, user_agent, ip, method, created_at, last_seen_at, expires_at, remember_me
                            """,
                            SessionEntity.class)
                        .setParameter(1, id))
                .stream()
                .findFirst()
                .map(JpaSessionStore::session));
  }

  @Override
  public List<Session> forSubject(String subject) {
    return database.transaction(
        em ->
            em.createQuery(
                    "select s from SessionEntity s where s.subject = :subject and s.expiresAt > :now order by s.lastSeenAt desc",
                    SessionEntity.class)
                .setParameter("subject", subject)
                .setParameter("now", Instant.now())
                .getResultStream()
                .map(JpaSessionStore::session)
                .toList());
  }

  @Override
  public void addClient(String id, String clientIdentifier) {
    // Native SQL: only for a session that still exists, and a repeated client is ignored, in one
    // statement.
    database.transaction(
        em ->
            em.createNativeQuery(
                    """
                    INSERT INTO session_clients (session_id, client_identifier)
                    SELECT id, ?1 FROM sessions WHERE id = ?2
                    ON CONFLICT DO NOTHING
                    """)
                .setParameter(1, clientIdentifier)
                .setParameter(2, id)
                .executeUpdate());
  }

  @Override
  public Set<String> clients(String id) {
    return database.transaction(
        em ->
            new LinkedHashSet<>(
                em.createQuery(
                        "select c.clientIdentifier from SessionClientEntity c where c.sessionId = :id order by c.clientIdentifier",
                        String.class)
                    .setParameter("id", id)
                    .getResultList()));
  }

  @Override
  public long countActive() {
    return database.transaction(
        em ->
            em.createQuery("select count(s) from SessionEntity s where s.expiresAt > :now", Long.class)
                .setParameter("now", Instant.now())
                .getSingleResult());
  }
}

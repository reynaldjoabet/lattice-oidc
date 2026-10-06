package com.lattice.oidc.stores;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.inject.Singleton;

/** {@link SessionStore} in memory, for one server (development and tests). */
@Singleton
public final class InMemorySessionStore implements SessionStore {

  private final Map<String, Session> sessions = new ConcurrentHashMap<>();
  private final Map<String, Set<String>> clients = new ConcurrentHashMap<>();

  private static boolean live(Session session) {
    return session.expiresAt().isAfter(Instant.now());
  }

  @Override
  public void create(Session session) {
    sessions.values().removeIf(existing -> !live(existing));
    sessions.put(session.id(), session);
  }

  @Override
  public Optional<Session> find(String id) {
    return id == null ? Optional.empty() : Optional.ofNullable(sessions.get(id)).filter(InMemorySessionStore::live);
  }

  @Override
  public void touch(String id, Instant now, Duration interval) {
    sessions.computeIfPresent(
        id,
        (key, session) ->
            session.lastSeenAt().plus(interval).isBefore(now)
                ? new Session(
                    session.id(), session.subject(), session.userAgent(), session.ip(), session.method(),
                    session.createdAt(), now, session.expiresAt(), session.rememberMe())
                : session);
  }

  @Override
  public Optional<Session> end(String id) {
    if (id == null) {
      return Optional.empty();
    }
    clients.remove(id);
    return Optional.ofNullable(sessions.remove(id));
  }

  @Override
  public List<Session> forSubject(String subject) {
    return sessions.values().stream()
        .filter(session -> session.subject().equals(subject) && live(session))
        .sorted(Comparator.comparing(Session::lastSeenAt).reversed())
        .toList();
  }

  @Override
  public void addClient(String id, String clientIdentifier) {
    if (sessions.containsKey(id)) {
      clients.computeIfAbsent(id, ignored -> java.util.Collections.synchronizedSet(new LinkedHashSet<>())).add(clientIdentifier);
    }
  }

  @Override
  public Set<String> clients(String id) {
    Set<String> found = clients.get(id);
    if (found == null) {
      return Set.of();
    }
    synchronized (found) {
      return Set.copyOf(found);
    }
  }

  @Override
  public long countActive() {
    return sessions.values().stream().filter(InMemorySessionStore::live).count();
  }
}

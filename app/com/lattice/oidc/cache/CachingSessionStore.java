package com.lattice.oidc.cache;

import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.metrics.Metrics;
import com.lattice.oidc.stores.SessionStore;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

/**
 * Caches the lookup made on every signed-in request, a session by id. Ending a session or recording
 * activity invalidates it on every server, so a sign-out takes effect everywhere at once. Activity is
 * recorded at most once per touch interval; while the cached copy shows recent activity, nothing is
 * written. Listings and client sets always go to the store.
 */
@Singleton
public final class CachingSessionStore implements SessionStore {

  static final String REGION = "session";

  private final SessionStore store;
  private final ReadCache cache;
  private final Metrics metrics;

  @Inject
  public CachingSessionStore(@Named("backing") SessionStore store, ReadCache cache, Metrics metrics) {
    this.store = store;
    this.cache = cache;
    this.metrics = metrics;
  }

  @Override
  public void create(Session session) {
    store.create(session);
  }

  @Override
  public Optional<Session> find(String id) {
    if (id == null) {
      return Optional.empty();
    }
    Optional<Session> cached = cache.get(REGION, id).map(json -> Jsons.read(json, Session.class));
    metrics.cacheLookup(REGION, cached.isPresent());
    if (cached.isPresent()) {
      return cached.filter(session -> session.expiresAt().isAfter(Instant.now()));
    }
    Optional<Session> session = store.find(id);
    session.ifPresent(found -> cache.put(REGION, id, Jsons.write(found)));
    return session;
  }

  @Override
  public void touch(String id, Instant now, Duration interval) {
    Optional<Session> cached = cache.get(REGION, id).map(json -> Jsons.read(json, Session.class));
    if (cached.isPresent() && !cached.get().lastSeenAt().plus(interval).isBefore(now)) {
      return; // Recent enough: the store wouldn't write either.
    }
    store.touch(id, now, interval);
    cache.invalidate(REGION, id);
  }

  @Override
  public Optional<Session> end(String id) {
    Optional<Session> ended = store.end(id);
    if (id != null) {
      cache.invalidate(REGION, id);
    }
    return ended;
  }

  @Override
  public List<Session> forSubject(String subject) {
    return store.forSubject(subject);
  }

  @Override
  public void addClient(String id, String clientIdentifier) {
    store.addClient(id, clientIdentifier);
  }

  @Override
  public Set<String> clients(String id) {
    return store.clients(id);
  }

  @Override
  public long countActive() {
    return store.countActive();
  }
}

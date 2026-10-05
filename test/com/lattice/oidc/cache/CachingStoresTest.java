package com.lattice.oidc.cache;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.lattice.oidc.metrics.Metrics;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.InMemorySessionStore;
import com.lattice.oidc.stores.SessionStore;
import com.lattice.oidc.stores.SessionStore.Session;
import com.lattice.oidc.stores.UserStore;
import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Test;

/** The read cache in front of the user and session stores, with per-server caches. */
public class CachingStoresTest {

  private static final Metrics METRICS =
      new Metrics(new play.inject.DelegateApplicationLifecycle(new play.api.inject.DefaultApplicationLifecycle()));

  private static final Config CONFIG =
      ConfigFactory.parseMap(Map.of("lattice.cache.ttl", "30 seconds", "lattice.cache.maximum-size", 1000));

  /** A user store that counts lookups by subject. */
  private static final class CountingUserStore implements UserStore {
    final Map<String, User> users = new ConcurrentHashMap<>();
    final AtomicInteger lookups = new AtomicInteger();

    @Override
    public Optional<User> bySubject(String subject) {
      lookups.incrementAndGet();
      return Optional.ofNullable(users.get(subject));
    }

    @Override
    public Optional<User> byLoginId(String loginId) {
      return Optional.empty();
    }

    @Override
    public Optional<User> byEmail(String email) {
      return Optional.empty();
    }

    @Override
    public Optional<User> byPhoneNumber(String phoneNumber) {
      return Optional.empty();
    }

    @Override
    public void save(User user) {
      users.put(user.getSubject(), user);
    }
  }

  /** A session store that counts lookups and writes of activity. */
  private static final class CountingSessionStore implements SessionStore {
    final InMemorySessionStore store = new InMemorySessionStore();
    final AtomicInteger lookups = new AtomicInteger();
    final AtomicInteger touches = new AtomicInteger();

    @Override
    public void create(Session session) {
      store.create(session);
    }

    @Override
    public Optional<Session> find(String id) {
      lookups.incrementAndGet();
      return store.find(id);
    }

    @Override
    public void touch(String id, Instant now, Duration interval) {
      touches.incrementAndGet();
      store.touch(id, now, interval);
    }

    @Override
    public Optional<Session> end(String id) {
      return store.end(id);
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

  private static User user(String subject, String passwordHash) {
    return new User(subject, "john", passwordHash, Map.of("name", "John", "email", "john@example.com"), Map.of(), List.of());
  }

  private static Session session(String id, Instant lastSeen, Instant expires) {
    return new Session(id, "1001", "ua", "127.0.0.1", "Password", lastSeen, lastSeen, expires, false);
  }

  @Test
  public void usersAreServedFromTheCacheUntilTheyChange() {
    CountingUserStore backing = new CountingUserStore();
    backing.save(user("1001", "old-hash"));
    CachingUserStore users = new CachingUserStore(backing, new LocalReadCache(CONFIG, new LocalInvalidationBus(), METRICS), METRICS);

    assertEquals("old-hash", users.bySubject("1001").orElseThrow().passwordHash());
    assertEquals("old-hash", users.bySubject("1001").orElseThrow().passwordHash());
    assertEquals("the second lookup is a cache hit", 1, backing.lookups.get());
    assertEquals("claims survive the cache", "John", users.bySubject("1001").orElseThrow().getClaim("name", null));

    users.save(user("1001", "new-hash"));
    assertEquals("a new password is seen at once", "new-hash", users.bySubject("1001").orElseThrow().passwordHash());
  }

  @Test
  public void aSignOutOnOneServerIsSeenOnEveryServer() {
    CountingSessionStore shared = new CountingSessionStore();
    LocalInvalidationBus bus = new LocalInvalidationBus();
    CachingSessionStore serverA = new CachingSessionStore(shared, new LocalReadCache(CONFIG, bus, METRICS), METRICS);
    CachingSessionStore serverB = new CachingSessionStore(shared, new LocalReadCache(CONFIG, bus, METRICS), METRICS);
    Instant now = Instant.now();
    shared.create(session("s1", now, now.plusSeconds(3600)));

    assertTrue(serverA.find("s1").isPresent());
    assertTrue(serverA.find("s1").isPresent());
    assertEquals("server A answers from its cache", 1, shared.lookups.get());

    serverB.end("s1");
    assertTrue("server A drops its copy when B signs out", serverA.find("s1").isEmpty());
  }

  @Test
  public void anExpiredSessionIsNotServedFromTheCache() throws InterruptedException {
    CountingSessionStore backing = new CountingSessionStore();
    CachingSessionStore sessions = new CachingSessionStore(backing, new LocalReadCache(CONFIG, new LocalInvalidationBus(), METRICS), METRICS);
    Instant now = Instant.now();
    backing.create(session("s1", now, now.plusMillis(300)));
    assertTrue(sessions.find("s1").isPresent());
    Thread.sleep(400);
    assertTrue("the cached copy has passed the session's lifetime", sessions.find("s1").isEmpty());
  }

  @Test
  public void recentActivityIsNotWrittenAgain() {
    CountingSessionStore backing = new CountingSessionStore();
    CachingSessionStore sessions = new CachingSessionStore(backing, new LocalReadCache(CONFIG, new LocalInvalidationBus(), METRICS), METRICS);
    Instant now = Instant.now();
    backing.create(session("s1", now, now.plusSeconds(3600)));
    sessions.find("s1");
    for (int i = 0; i < 10; i++) {
      sessions.touch("s1", now.plusSeconds(5), Duration.ofMinutes(1));
    }
    assertEquals("nothing to write within the touch interval", 0, backing.touches.get());
    sessions.touch("s1", now.plusSeconds(90), Duration.ofMinutes(1));
    assertEquals(1, backing.touches.get());
    assertEquals(now.plusSeconds(90), sessions.find("s1").orElseThrow().lastSeenAt());
  }
}

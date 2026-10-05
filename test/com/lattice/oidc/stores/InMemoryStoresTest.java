package com.lattice.oidc.stores;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.lattice.oidc.stores.SessionStore.Session;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.Test;

/** The in-memory stores: the behaviour the PostgreSQL stores must match. */
public class InMemoryStoresTest {

  @Test
  public void floodingOneKindOfStateDoesNotPushOutAnother() {
    InMemoryEphemeralStore store = new InMemoryEphemeralStore(10);
    store.put("reset-token", "real", null, "1001", "{}", Duration.ofMinutes(15));
    store.put("interaction:authz", "first", "browser", null, "{}", Duration.ofMinutes(1));
    for (int i = 0; i < 100; i++) {
      store.put("interaction:authz", "flood-" + i, "attacker", null, "{}", Duration.ofMinutes(10));
    }
    assertEquals("each kind is bounded", 10, store.count("interaction:authz"));
    assertTrue("the entry closest to expiry went first", store.get("interaction:authz", "first").isEmpty());
    assertTrue("other kinds are untouched", store.get("reset-token", "real").isPresent());
  }

  @Test
  public void takeIsSingleUseAndExpiredEntriesAreGone() {
    InMemoryEphemeralStore store = new InMemoryEphemeralStore();
    store.put("ns", "key", "owner", "1001", "{\"a\":1}", Duration.ofMinutes(1));
    assertEquals("{\"a\":1}", store.take("ns", "key").orElseThrow().json());
    assertTrue(store.take("ns", "key").isEmpty());

    store.put("ns", "old", null, "1001", "{}", Duration.ofMillis(-1));
    assertTrue(store.get("ns", "old").isEmpty());
    assertTrue(store.bySubject("ns", "1001").isEmpty());
  }

  @Test
  public void entriesAreListedAndDeletedByAccount() {
    InMemoryEphemeralStore store = new InMemoryEphemeralStore();
    store.put("alerts", "a", null, "1001", "{}", Duration.ofMinutes(1));
    store.put("alerts", "b", null, "1001", "{}", Duration.ofMinutes(2));
    store.put("alerts", "c", null, "1002", "{}", Duration.ofMinutes(1));
    assertEquals(List.of("a", "b"), store.bySubject("alerts", "1001").stream().map(EphemeralStore.Entry::key).toList());
    assertEquals(2, store.deleteBySubject("alerts", "1001"));
    assertEquals(1, store.count("alerts"));
  }

  @Test
  public void sessionsAreTouchedAtMostOncePerInterval() {
    InMemorySessionStore store = new InMemorySessionStore();
    Instant start = Instant.now().minusSeconds(120);
    store.create(new Session("s1", "1001", "ua", "127.0.0.1", "Password", start, start, start.plusSeconds(3600), false));
    store.touch("s1", start.plusSeconds(30), Duration.ofMinutes(1));
    assertEquals("within the interval: no write", start, store.find("s1").orElseThrow().lastSeenAt());
    Instant later = start.plusSeconds(90);
    store.touch("s1", later, Duration.ofMinutes(1));
    assertEquals(later, store.find("s1").orElseThrow().lastSeenAt());

    store.addClient("s1", "client-a");
    store.addClient("s1", "client-a");
    assertEquals(1, store.clients("s1").size());
    assertTrue(store.end("s1").isPresent());
    assertTrue(store.find("s1").isEmpty());
    assertTrue(store.clients("s1").isEmpty());
  }

  @Test
  public void sessionsPastTheirLifetimeAreGone() {
    InMemorySessionStore store = new InMemorySessionStore();
    Instant past = Instant.now().minusSeconds(60);
    store.create(new Session("s1", "1001", null, null, "Password", past, past, past.plusSeconds(1), false));
    assertTrue(store.find("s1").isEmpty());
    assertEquals(0, store.countActive());
  }

  @Test
  public void countersCountWithinTheirWindow() {
    InMemoryCounterStore counters = new InMemoryCounterStore();
    assertEquals(1, counters.increment("login:ip:1", Duration.ofMinutes(15)));
    assertEquals(2, counters.increment("login:ip:1", Duration.ofMinutes(15)));
    assertEquals(2, counters.count("login:ip:1"));
    counters.increment("login:account-ip:john|1", Duration.ofMinutes(15));
    counters.increment("login:account-ip:john|2", Duration.ofMinutes(15));
    counters.resetPrefix("login:account-ip:john|");
    assertEquals(0, counters.count("login:account-ip:john|1"));
    assertEquals(1, counters.countAtLeast("login:ip:", 2));

    counters.increment("short", Duration.ofMillis(-1));
    assertEquals("an ended window counts as zero", 0, counters.count("short"));
    assertFalse(counters.countAtLeast("short", 1) > 0);
  }
}

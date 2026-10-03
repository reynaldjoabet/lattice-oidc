package com.lattice.oidc.security;

import static org.junit.Assert.assertTrue;

import com.lattice.oidc.OidcTestSupport;
import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.stores.UserStore;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;
import play.Application;
import play.test.Helpers;

public class CacheIsolationTest {

  /**
   * A flood of pending flows (created by unauthenticated requests) fills only the interactions
   * cache: older flows are evicted, login sessions are not.
   */
  @Test
  public void floodingInteractionsDoesNotEvictLoginSessions() throws InterruptedException {
    Application app =
        OidcTestSupport.app(
            new FakeAuthleteApi(),
            Map.of("play.cache.caffeine.caches.lattice-interactions.maximum-size", 10));
    Helpers.start(app);
    try {
      UserSessions sessions = app.injector().instanceOf(UserSessions.class);
      Interactions interactions = app.injector().instanceOf(Interactions.class);
      UserStore users = app.injector().instanceOf(UserStore.class);

      String sid =
          sessions.login(users.byLoginId("john").orElseThrow(), 0L, null, new HashMap<>());
      interactions.put("authz", "first", "browser", "pending");

      for (int i = 0; i < 5_000; i++) {
        interactions.put("authz", "flood-" + i, "attacker", "junk");
      }

      // Caffeine evicts asynchronously; give its maintenance a moment.
      boolean firstEvicted = false;
      for (int i = 0; i < 50 && !firstEvicted; i++) {
        firstEvicted = interactions.get("authz", "first", "browser", String.class).isEmpty();
        Thread.sleep(20);
      }
      assertTrue("the interactions cache is bounded", firstEvicted);
      assertTrue("login sessions live in their own cache", sessions.isActive(sid));
    } finally {
      Helpers.stop(app);
    }
  }
}

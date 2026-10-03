package com.lattice.oidc.filters;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.get;
import static com.lattice.oidc.OidcTestSupport.post;
import static com.lattice.oidc.OidcTestSupport.route;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static play.test.Helpers.contentAsString;

import com.lattice.oidc.client.FakeAuthleteApi;
import java.util.Map;
import org.junit.Test;
import play.Application;
import play.mvc.Result;
import play.test.Helpers;

public class FiltersAndErrorsTest {

  @Test
  public void unknownApiPathGetsOAuthStyleJsonEvenForWildcardAccept() {
    Application app = app(new FakeAuthleteApi());
    Helpers.running(
        app,
        () -> {
          Result r = route(app, get("/api/nope").header("Accept", "*/*"));
          assertEquals(404, r.status());
          assertTrue(r.contentType().orElse("").contains("json"));
          assertTrue(contentAsString(r).contains("\"error\":\"not_found\""));
        });
  }

  /**
   * A cross-site form post from a logged-in victim's browser carries the victim's cookies and no
   * CSRF token: it must be rejected before reaching the controller. (Play only checks requests
   * with a Cookie or Authorization header; without them there is no ambient credential to abuse.)
   */
  @Test
  public void forgedBrowserFormPostIsRejectedWithHtmlWithoutDetails() {
    Application app = app(new FakeAuthleteApi());
    Helpers.running(
        app,
        () -> {
          Result r =
              route(
                  app,
                  post("/api/device/complete", Map.of("userCode", "ABCD", "authorized", "true"))
                      .header("Cookie", "PLAY_SESSION=anything"));
          assertEquals(contentAsString(r), 403, r.status());
          assertTrue(r.contentType().orElse("").contains("html"));
          assertTrue("rejected requests still get a request id", r.header("X-Request-ID").isPresent());
          assertFalse(contentAsString(r).contains("Exception"));
        });
  }

  @Test
  public void requestIdIsEchoedOrGenerated() {
    Application app = app(new FakeAuthleteApi());
    Helpers.running(
        app,
        () -> {
          Result given = route(app, get("/health/live").header("X-Request-ID", "abc-123"));
          assertEquals("abc-123", given.header("X-Request-ID").orElse(null));

          Result injected = route(app, get("/health/live").header("X-Request-ID", "bad\nvalue"));
          String id = injected.header("X-Request-ID").orElse("");
          assertNotEquals("bad\nvalue", id);
          assertEquals(36, id.length());
        });
  }

  @Test
  public void hstsRedirectsPlainHttpAndMarksHttpsResponses() {
    Application app = app(new FakeAuthleteApi(), Map.of("lattice.security.hsts.enabled", true));
    Helpers.running(
        app,
        () -> {
          Result redirect = route(app, get("/api/device/verification").host("localhost"));
          assertEquals(301, redirect.status());
          assertEquals(
              "https://localhost/api/device/verification", redirect.redirectLocation().orElse(null));

          Result post = route(app, post("/api/token", Map.of("grant_type", "x")).host("localhost"));
          assertEquals("POST over HTTP is refused, not redirected", 403, post.status());

          Result probe = route(app, get("/health/live"));
          assertEquals("health probes stay reachable over HTTP", 200, probe.status());

          Result secure = route(app, get("/health/ready").secure(true));
          assertFalse(secure.header("Strict-Transport-Security").isPresent());
          Result page = route(app, get("/api/device/verification").secure(true));
          assertTrue(page.header("Strict-Transport-Security").orElse("").startsWith("max-age="));
        });
  }
}

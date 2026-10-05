package com.lattice.oidc.controllers;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.get;
import static com.lattice.oidc.OidcTestSupport.post;
import static com.lattice.oidc.OidcTestSupport.route;
import static com.lattice.oidc.OidcTestSupport.withCsrf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static play.test.Helpers.contentAsString;

import com.lattice.oidc.client.FakeAuthleteApi;
import java.util.Map;
import org.junit.After;
import org.junit.Test;
import play.Application;
import play.mvc.Result;
import play.test.Helpers;

/** Prometheus metrics at /metrics. */
public class MetricsTest {

  private Application app;

  private void start(Map<String, Object> config) {
    app = app(new FakeAuthleteApi(), config);
    Helpers.start(app);
  }

  @After
  public void stop() {
    if (app != null) {
      Helpers.stop(app);
    }
  }

  @Test
  public void metricsAreOffByDefault() {
    start(Map.of());
    assertEquals(404, route(app, get("/metrics")).status());
  }

  @Test
  public void metricsCountRequestsSignInsAndSessions() {
    start(Map.of("lattice.metrics.enabled", true));
    route(app, withCsrf(post("/account/login", Map.of("loginId", "john", "password", "wrong", "next", "account"))));
    route(app, withCsrf(post("/account/login", Map.of("loginId", "john", "password", "john", "next", "account"))));

    Result metrics = route(app, get("/metrics"));
    assertEquals(200, metrics.status());
    String text = contentAsString(metrics);
    assertTrue(text.contains("lattice_audit_events_total{event=\"LOGIN_FAILED\"} 1.0"));
    assertTrue(text.contains("lattice_audit_events_total{event=\"LOGIN_SUCCEEDED\"} 1.0"));
    assertTrue("requests are tagged by route", text.contains("route=\"/account/login\""));
    assertTrue(text.contains("lattice_sessions_active 1.0"));
    assertTrue("JVM figures are included", text.contains("jvm_memory_used_bytes"));
    assertFalse("no user data in tags", text.contains("john"));
  }

  @Test
  public void aTokenCanBeRequired() {
    start(Map.of("lattice.metrics.enabled", true, "lattice.metrics.token", "scrape-secret"));
    assertEquals(401, route(app, get("/metrics")).status());
    assertEquals(401, route(app, get("/metrics").header("Authorization", "Bearer wrong")).status());
    assertEquals(200, route(app, get("/metrics").header("Authorization", "Bearer scrape-secret")).status());
  }
}

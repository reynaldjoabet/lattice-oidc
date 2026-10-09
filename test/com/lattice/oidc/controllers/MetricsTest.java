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
import com.lattice.oidc.common.Mailer;
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
  public void storageThreadPoolMailLogsAndJvmAreMeasured() {
    start(Map.of("lattice.metrics.enabled", true, "lattice.cache.type", "local"));
    route(app, withCsrf(post("/account/login", Map.of("loginId", "john", "password", "john", "next", "account"))));
    app.injector().instanceOf(Mailer.class).send("jane@example.com", "Hello", "Text");

    String text = contentAsString(route(app, get("/metrics")));
    assertTrue("pending state by namespace", text.contains("lattice_short_lived_entries{namespace="));
    assertTrue(text.contains("lattice_second_factor_accounts 0.0"));
    assertTrue(text.contains("lattice_second_factor_previous_key{kind=\"authenticator_secrets\"} 0.0"));
    assertTrue(text.contains("lattice_authlete_executor_tasks{state=\"queued\"}"));
    assertTrue(text.contains("lattice_authlete_executor_threads 32.0"));
    assertTrue("no SMTP host: the email is logged", text.contains("lattice_mail_messages_seconds_count{outcome=\"logged\"} 1"));
    assertTrue("Caffeine's own figures", text.contains("cache_size{cache=\"read_cache\"}"));
    assertTrue(text.contains("logback_events_total{level=\"warn\"}"));
    assertTrue(text.contains("jvm_info{"));
    assertTrue("which build is running", text.contains("lattice_build_info{revision=\"" + com.lattice.oidc.metrics.Metrics.shortRevision() + "\",version=\"" + com.lattice.oidc.BuildInfo.version + "\"} 1"));
    assertTrue(text.contains("jvm_memory_usage_after_gc"));
    assertFalse("no user data in tags", text.contains("jane@example.com"));
  }

  @Test
  public void aTokenCanBeRequired() {
    start(Map.of("lattice.metrics.enabled", true, "lattice.metrics.token", "scrape-secret"));
    assertEquals(401, route(app, get("/metrics")).status());
    assertEquals(401, route(app, get("/metrics").header("Authorization", "Bearer wrong")).status());
    assertEquals(200, route(app, get("/metrics").header("Authorization", "Bearer scrape-secret")).status());
  }
}

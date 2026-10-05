package com.lattice.oidc.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.binder.jvm.ClassLoaderMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmGcMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmMemoryMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmThreadMetrics;
import io.micrometer.core.instrument.binder.system.ProcessorMetrics;
import io.micrometer.core.instrument.binder.system.UptimeMetrics;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import javax.inject.Inject;
import javax.inject.Singleton;
import play.inject.ApplicationLifecycle;

/**
 * The server's metrics, served in Prometheus format at {@code /metrics} ({@code
 * lattice.metrics.enabled}). Each application has its own registry; values are live.
 *
 * <p>Besides JVM and process figures: HTTP requests by route and status, audit events (sign-ins,
 * consents, ...), Authlete API calls, active sessions, the read cache and the PostgreSQL pool.
 * Tags never contain user data, so the number of series stays bounded.
 */
@Singleton
public final class Metrics {

  private final PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);

  @Inject
  public Metrics(ApplicationLifecycle lifecycle) {
    new ClassLoaderMetrics().bindTo(registry);
    new JvmMemoryMetrics().bindTo(registry);
    new JvmThreadMetrics().bindTo(registry);
    new ProcessorMetrics().bindTo(registry);
    new UptimeMetrics().bindTo(registry);
    JvmGcMetrics gc = new JvmGcMetrics();
    gc.bindTo(registry);
    lifecycle.addStopHook(
        () -> {
          gc.close();
          registry.close();
          return CompletableFuture.completedFuture(null);
        });
  }

  public MeterRegistry registry() {
    return registry;
  }

  /** The current values in Prometheus text format. */
  public String scrape() {
    return registry.scrape();
  }

  /** Counts an audit event ({@code lattice_audit_events_total{event="LOGIN_FAILED"}}). */
  public void auditEvent(String event) {
    Counter.builder("lattice.audit.events")
        .description("Security events recorded in the audit trail")
        .tag("event", event)
        .register(registry)
        .increment();
  }

  /** Records an HTTP request. {@code route} is the route pattern, never the raw path. */
  public void httpRequest(String method, String route, int status, Duration duration) {
    Timer.builder("http.server.requests")
        .description("HTTP requests handled")
        .tag("method", method)
        .tag("route", route)
        .tag("status", Integer.toString(status))
        .publishPercentileHistogram()
        .register(registry)
        .record(duration);
  }

  /** Counts a read-cache lookup ({@code lattice_read_cache_lookups_total{region,result}}). */
  public void cacheLookup(String region, boolean hit) {
    Counter.builder("lattice.read.cache.lookups")
        .description("Read cache lookups")
        .tag("region", region)
        .tag("result", hit ? "hit" : "miss")
        .register(registry)
        .increment();
  }

  /** Records a call to the Authlete API, by client method and outcome. */
  public void authleteCall(String operation, boolean success, Duration duration) {
    Timer.builder("lattice.authlete.calls")
        .description("Calls to the Authlete API")
        .tag("operation", operation)
        .tag("outcome", success ? "success" : "error")
        .register(registry)
        .record(duration);
  }
}

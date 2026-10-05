package com.lattice.oidc.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.binder.jvm.ClassLoaderMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmGcMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmHeapPressureMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmInfoMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmMemoryMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmThreadMetrics;
import io.micrometer.core.instrument.binder.logging.LogbackMetrics;
import io.micrometer.core.instrument.binder.system.FileDescriptorMetrics;
import io.micrometer.core.instrument.binder.system.ProcessorMetrics;
import io.micrometer.core.instrument.binder.system.UptimeMetrics;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.inject.ApplicationLifecycle;

/**
 * The server's metrics, served in Prometheus format at {@code /metrics} ({@code
 * lattice.metrics.enabled}). Each application has its own registry; values are live.
 *
 * <ul>
 *   <li>JVM and process: memory, heap pressure, garbage collection, threads, classes, CPU, open
 *       files, uptime, JVM version, and log events by level.
 *   <li>HTTP requests by route and status, and audit events (sign-ins, consents, ...).
 *   <li>Authlete API calls, and the thread pool that runs them.
 *   <li>Storage: active sessions, short-lived entries, the read cache, the PostgreSQL pool, cleanup
 *       and cache invalidation, Redis commands and pool.
 *   <li>Outbound: webhook deliveries, LDAP searches and binds, upstream identity providers, email.
 *   <li>Two-step verification: adoption, and what is still under a previous key.
 * </ul>
 *
 * Tags never contain user data, so the number of series stays bounded. Gauges that query storage
 * are refreshed before a scrape, at most every {@link #REFRESH_INTERVAL}.
 */
@Singleton
public final class Metrics {

  private static final Logger LOG = LoggerFactory.getLogger(Metrics.class);
  static final Duration REFRESH_INTERVAL = Duration.ofSeconds(30);

  private final PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
  private final List<Runnable> refreshers = new CopyOnWriteArrayList<>();
  private Instant refreshedAt = Instant.EPOCH;

  @Inject
  public Metrics(ApplicationLifecycle lifecycle) {
    new ClassLoaderMetrics().bindTo(registry);
    new JvmMemoryMetrics().bindTo(registry);
    new JvmThreadMetrics().bindTo(registry);
    new ProcessorMetrics().bindTo(registry);
    new UptimeMetrics().bindTo(registry);
    new JvmInfoMetrics().bindTo(registry);
    new FileDescriptorMetrics().bindTo(registry);
    JvmGcMetrics gc = new JvmGcMetrics();
    gc.bindTo(registry);
    JvmHeapPressureMetrics heapPressure = new JvmHeapPressureMetrics();
    heapPressure.bindTo(registry);
    LogbackMetrics logs = new LogbackMetrics();
    logs.bindTo(registry);
    lifecycle.addStopHook(
        () -> {
          gc.close();
          heapPressure.close();
          logs.close();
          registry.close();
          return CompletableFuture.completedFuture(null);
        });
  }

  public MeterRegistry registry() {
    return registry;
  }

  /** The current values in Prometheus text format. */
  public String scrape() {
    refresh();
    return registry.scrape();
  }

  /**
   * Registers work that updates gauges from storage (a query, a Redis scan). It runs before a scrape,
   * at most every {@link #REFRESH_INTERVAL}, so frequent scrapes don't load the database.
   */
  public void beforeScrape(Runnable refresher) {
    refreshers.add(refresher);
  }

  private synchronized void refresh() {
    Instant now = Instant.now();
    if (now.isBefore(refreshedAt.plus(REFRESH_INTERVAL))) {
      return;
    }
    refreshedAt = now;
    for (Runnable refresher : refreshers) {
      try {
        refresher.run();
      } catch (RuntimeException e) {
        // A gauge keeps its last value; the scrape itself still succeeds.
        LOG.warn("Could not refresh a metric: {}", e.getMessage());
      }
    }
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

  /**
   * Counts a webhook delivery attempt by endpoint (its position in the configuration and its host;
   * the path may hold a secret) and outcome: delivered, retry (failed, will be retried) or failed.
   */
  public void webhookDelivery(int endpoint, String host, String outcome) {
    Counter.builder("lattice.webhook.deliveries")
        .description("Webhook delivery attempts")
        .tag("endpoint", Integer.toString(endpoint))
        .tag("host", host)
        .tag("outcome", outcome)
        .register(registry)
        .increment();
  }

  /** Records an LDAP search or bind; outcome is success, not_found, invalid_credentials or error. */
  public void ldapOperation(String operation, String outcome, Duration duration) {
    Timer.builder("lattice.ldap.operations")
        .description("LDAP searches and binds")
        .tag("operation", operation)
        .tag("outcome", outcome)
        .register(registry)
        .record(duration);
  }

  /** Records a sign-in completed with an upstream provider (token, ID token and UserInfo). */
  public void identityProviderSignIn(String provider, boolean success, Duration duration) {
    Timer.builder("lattice.identity.provider.sign.ins")
        .description("Sign-ins completed with upstream identity providers")
        .tag("provider", provider)
        .tag("outcome", success ? "success" : "error")
        .register(registry)
        .record(duration);
  }

  /** Records an email; outcome is sent, failed, or logged (no SMTP host configured). */
  public void mail(String outcome, Duration duration) {
    Timer.builder("lattice.mail.messages")
        .description("Emails sent over SMTP")
        .tag("outcome", outcome)
        .register(registry)
        .record(duration);
  }

  /** Records a Redis command (GET, SET, EVAL, ...) and whether it failed. */
  public void redisCommand(String command, boolean success, Duration duration) {
    Timer.builder("lattice.redis.commands")
        .description("Redis commands")
        .tag("command", command)
        .tag("outcome", success ? "success" : "error")
        .register(registry)
        .record(duration);
  }

  /** Counts rows deleted by the storage cleanup, by table. */
  public void storageCleanup(String table, long rows) {
    Counter.builder("lattice.storage.cleanup.deleted")
        .description("Expired rows deleted by the storage cleanup")
        .tag("table", table)
        .register(registry)
        .increment(rows);
  }

  /** Counts a failed storage cleanup run. */
  public void storageCleanupFailure() {
    Counter.builder("lattice.storage.cleanup.failures")
        .description("Storage cleanup runs that failed")
        .register(registry)
        .increment();
  }

  /** Counts a reconnection of the PostgreSQL cache-invalidation listener (each one clears the cache). */
  public void invalidationListenerReconnect() {
    Counter.builder("lattice.cache.invalidation.reconnects")
        .description("Reconnections of the cache-invalidation listener; each clears the local cache")
        .register(registry)
        .increment();
  }
}

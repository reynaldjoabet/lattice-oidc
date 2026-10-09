package com.lattice.oidc.common;

import com.lattice.oidc.client.AuthleteExecutionContext;
import com.lattice.oidc.client.AuthleteHealth;
import com.lattice.oidc.metrics.Metrics;
import com.lattice.oidc.stores.postgres.PostgresDatabase;
import com.lattice.oidc.stores.redis.RedisConnection;
import com.typesafe.config.Config;
import io.micrometer.core.instrument.Gauge;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import play.inject.Injector;

/**
 * The services Lattice depends on: Authlete always, PostgreSQL and Redis when configured. Served
 * at {@code /health/dependencies} and as {@code lattice_dependency_up{dependency}} (1 or 0),
 * for monitoring and alerts.
 *
 * <p>Deliberately not part of readiness: every replica shares these services, so an outage would
 * make every replica unready at once, and the gateway would answer with its own error instead of
 * Lattice's "temporarily unavailable" page. Alert on the metric instead.
 */
@Singleton
public final class DependencyChecks {

  /** How long one check may take. */
  static final Duration TIMEOUT = Duration.ofSeconds(5);

  private final Map<String, Supplier<Map<String, String>>> checks = new LinkedHashMap<>();
  private final Map<String, AtomicInteger> up = new ConcurrentHashMap<>();
  private final AuthleteExecutionContext executionContext;

  @Inject
  public DependencyChecks(
      AuthleteHealth authlete,
      Config config,
      Injector injector,
      Metrics metrics,
      AuthleteExecutionContext executionContext) {
    this.executionContext = executionContext;
    checks.put("authlete", authlete::check);
    if (config.getString("lattice.storage").trim().equalsIgnoreCase("postgres")) {
      PostgresDatabase database = injector.instanceOf(PostgresDatabase.class);
      checks.put("postgres", () -> check(() -> database.queryOne("SELECT 1", row -> row.getInt(1))));
    }
    String shortLived = config.getString("lattice.short-lived-state").trim();
    String cache = config.getString("lattice.cache.type").trim();
    if (shortLived.equalsIgnoreCase("redis") || cache.equalsIgnoreCase("redis")) {
      RedisConnection redis = injector.instanceOf(RedisConnection.class);
      checks.put("redis", () -> check(() -> redis.client().ping()));
    }
    for (String name : checks.keySet()) {
      AtomicInteger value = new AtomicInteger(1);
      up.put(name, value);
      Gauge.builder("lattice.dependency.up", value, AtomicInteger::get)
          .description("Whether a service Lattice depends on answers (1) or not (0), on this server")
          .tag("dependency", name)
          .register(metrics.registry());
    }
    metrics.beforeScrape(this::run);
  }

  private static Map<String, String> check(Runnable call) {
    try {
      call.run();
      return Map.of("status", "UP");
    } catch (RuntimeException e) {
      return Map.of("status", "DOWN", "reason", "unreachable");
    }
  }

  /** Runs every check in parallel, each within {@link #TIMEOUT}; also updates the metric. */
  public Map<String, Map<String, String>> run() {
    Map<String, CompletableFuture<Map<String, String>>> running = new LinkedHashMap<>();
    checks.forEach(
        (name, check) ->
            running.put(
                name,
                CompletableFuture.supplyAsync(check, executionContext.current())
                    .completeOnTimeout(Map.of("status", "DOWN", "reason", "timeout"), TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)
                    .exceptionally(error -> Map.of("status", "DOWN", "reason", "error"))));
    Map<String, Map<String, String>> results = new LinkedHashMap<>();
    running.forEach(
        (name, future) -> {
          Map<String, String> result = future.join();
          results.put(name, result);
          up.get(name).set("UP".equals(result.get("status")) ? 1 : 0);
        });
    return results;
  }
}

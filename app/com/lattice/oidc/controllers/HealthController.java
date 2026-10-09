package com.lattice.oidc.controllers;

import com.lattice.oidc.client.AuthleteExecutionContext;
import com.lattice.oidc.common.DependencyChecks;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import jakarta.inject.Inject;
import play.libs.Json;
import play.mvc.Controller;
import play.mvc.Result;

/**
 * Health endpoints.
 *
 * <ul>
 *   <li>{@code /health/live}: the process serves requests (liveness).
 *   <li>{@code /health/ready}: this replica can take traffic (readiness). It answers once the
 *       application has started (configuration loaded, database migrated), and checks nothing
 *       shared with the other replicas: an outage of Authlete or the database would otherwise take
 *       every replica out of the Service at once, and users would get the gateway's error instead
 *       of Lattice's "temporarily unavailable" page.
 *   <li>{@code /health/dependencies}: whether Authlete, PostgreSQL and Redis (those configured)
 *       answer; 503 if any doesn't. For monitoring and people, not for probes.
 * </ul>
 */
public final class HealthController extends Controller {

  private final DependencyChecks dependencies;
  private final AuthleteExecutionContext executionContext;

  @Inject
  public HealthController(DependencyChecks dependencies, AuthleteExecutionContext executionContext) {
    this.dependencies = dependencies;
    this.executionContext = executionContext;
  }

  public Result live() {
    return noStore(ok(Json.toJson(Map.of("status", "UP"))));
  }

  public Result ready() {
    return noStore(ok(Json.toJson(Map.of("status", "UP"))));
  }

  public CompletionStage<Result> dependencies() {
    return CompletableFuture.supplyAsync(dependencies::run, executionContext.current())
        .thenApply(
            checks -> {
              boolean up = checks.values().stream().allMatch(check -> "UP".equals(check.get("status")));
              Map<String, Object> body = new LinkedHashMap<>();
              body.put("status", up ? "UP" : "DOWN");
              body.put("checks", checks);
              return noStore(status(up ? OK : SERVICE_UNAVAILABLE, Json.toJson(body)));
            });
  }

  private static Result noStore(Result result) {
    return result.withHeader(CACHE_CONTROL, "no-store");
  }
}

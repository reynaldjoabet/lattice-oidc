package com.lattice.oidc.controllers;

import com.lattice.oidc.client.AuthleteExecutionContext;
import com.lattice.oidc.client.AuthleteHealth;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import jakarta.inject.Inject;
import play.libs.Json;
import play.mvc.Controller;
import play.mvc.Result;

/**
 * Liveness and readiness probes.
 *
 * <p>Liveness only says the process is serving requests. Readiness additionally requires the
 * Authlete client to be configured and the service configuration to be retrievable.
 */
public final class HealthController extends Controller {

  private static final Duration READY_TIMEOUT = Duration.ofSeconds(5);

  private final AuthleteHealth authlete;
  private final AuthleteExecutionContext executionContext;

  @Inject
  public HealthController(AuthleteHealth authlete, AuthleteExecutionContext executionContext) {
    this.authlete = authlete;
    this.executionContext = executionContext;
  }

  public Result live() {
    return noStore(ok(Json.toJson(Map.of("status", "UP"))));
  }

  public CompletionStage<Result> ready() {
    return CompletableFuture.supplyAsync(authlete::check, executionContext.current())
        .orTimeout(READY_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)
        .exceptionally(t -> Map.of("status", "DOWN", "reason", "timeout"))
        .thenApply(
            check -> {
              boolean up = "UP".equals(check.get("status"));
              Map<String, Object> body = new LinkedHashMap<>();
              body.put("status", up ? "UP" : "DOWN");
              body.put("checks", Map.of("authlete", check));
              return noStore(status(up ? OK : SERVICE_UNAVAILABLE, Json.toJson(body)));
            });
  }

  private static Result noStore(Result result) {
    return result.withHeader(CACHE_CONTROL, "no-store");
  }
}

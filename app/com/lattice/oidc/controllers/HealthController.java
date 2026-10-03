package com.lattice.oidc.controllers;

import com.authlete.common.api.AuthleteApi;
import com.lattice.oidc.client.AuthleteExecutionContext;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import javax.inject.Inject;
import javax.inject.Provider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

  private static final Logger LOG = LoggerFactory.getLogger(HealthController.class);
  private static final Duration READY_TIMEOUT = Duration.ofSeconds(5);

  private final Provider<AuthleteApi> api;
  private final AuthleteExecutionContext authleteEc;

  @Inject
  public HealthController(Provider<AuthleteApi> api, AuthleteExecutionContext authleteEc) {
    this.api = api;
    this.authleteEc = authleteEc;
  }

  public Result live() {
    return noStore(ok(Json.toJson(Map.of("status", "UP"))));
  }

  public CompletionStage<Result> ready() {
    return CompletableFuture.supplyAsync(this::checkAuthlete, authleteEc.current())
        .orTimeout(READY_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)
        .exceptionally(t -> Map.of("status", "DOWN", "reason", "timeout"))
        .thenApply(
            authlete -> {
              boolean up = "UP".equals(authlete.get("status"));
              Map<String, Object> body = new LinkedHashMap<>();
              body.put("status", up ? "UP" : "DOWN");
              body.put("checks", Map.of("authlete", authlete));
              return noStore(status(up ? OK : SERVICE_UNAVAILABLE, Json.toJson(body)));
            });
  }

  private Map<String, String> checkAuthlete() {
    AuthleteApi authlete;
    try {
      authlete = api.get();
    } catch (RuntimeException e) {
      LOG.warn("Authlete client is not configured: {}", e.getMessage());
      return Map.of("status", "DOWN", "reason", "not configured");
    }
    try {
      authlete.getServiceConfiguration(false);
      return Map.of("status", "UP");
    } catch (RuntimeException e) {
      LOG.warn("Authlete readiness check failed: {}", e.getMessage());
      return Map.of("status", "DOWN", "reason", "unreachable");
    }
  }

  private static Result noStore(Result result) {
    return result.withHeader(CACHE_CONTROL, "no-store");
  }
}

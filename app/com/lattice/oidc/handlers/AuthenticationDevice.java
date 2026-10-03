package com.lattice.oidc.handlers;

import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.common.LatticeConfig;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.inject.Inject;
import javax.inject.Singleton;
import play.libs.ws.WSClient;
import play.libs.ws.WSResponse;

/**
 * Client for the authentication device used by CIBA (Authlete's CIBA simulator API: {@code
 * /api/authenticate/sync|async|poll|result}). A real deployment replaces this with its push
 * notification / authenticator app integration.
 */
@Singleton
public final class AuthenticationDevice {

  /** Bounds accepted by the device for the user's decision time, in seconds. */
  static final int AUTH_TIMEOUT_MIN = 5;

  static final int AUTH_TIMEOUT_MAX = 60;

  public enum Outcome {
    ALLOW,
    DENY,
    TIMEOUT,
    UNKNOWN
  }

  private final WSClient ws;
  private final LatticeConfig.Ciba config;

  @Inject
  public AuthenticationDevice(WSClient ws, LatticeConfig config) {
    this.ws = ws;
    this.config = config.ciba();
  }

  /** Blocks until the user decides (or the device times out). */
  public Outcome sync(String user, String message, int timeoutSeconds, String authReqId) {
    Map<String, Object> r =
        post(
            "/api/authenticate/sync",
            request(user, message, timeoutSeconds, authReqId),
            config.requestTimeout().plusSeconds(timeoutSeconds));
    return outcome(r.get("result"));
  }

  /** Starts an asynchronous authentication; the device later calls back with the request id. */
  public String async(String user, String message, int timeoutSeconds, String authReqId) {
    return requestId(
        post("/api/authenticate/async", request(user, message, timeoutSeconds, authReqId), config.requestTimeout()));
  }

  /** Starts an authentication whose result is polled with {@link #result}. */
  public String poll(String user, String message, int timeoutSeconds, String authReqId) {
    return requestId(
        post("/api/authenticate/poll", request(user, message, timeoutSeconds, authReqId), config.requestTimeout()));
  }

  /** Polling result: {@code null} while the user has not decided yet. */
  public Outcome result(String requestId) {
    Map<String, Object> r =
        post("/api/authenticate/result", Map.of("request_id", requestId), config.requestTimeout());
    Object status = r.get("status");
    if ("active".equals(status)) {
      return null;
    }
    if ("timeout".equals(status)) {
      return Outcome.TIMEOUT;
    }
    return outcome(r.get("result"));
  }

  public static Outcome outcome(Object value) {
    if (value == null) {
      return Outcome.UNKNOWN;
    }
    return switch (value.toString()) {
      case "allow" -> Outcome.ALLOW;
      case "deny" -> Outcome.DENY;
      case "timeout" -> Outcome.TIMEOUT;
      default -> Outcome.UNKNOWN;
    };
  }

  private Map<String, Object> request(String user, String message, int timeout, String authReqId) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("workspace", config.workspace().orElseThrow(
        () -> new IllegalStateException("lattice.ciba.workspace (CIBA_AD_WORKSPACE) is not set")));
    body.put("user", user);
    body.put("message", message);
    body.put("timeout", timeout);
    body.put("actionize_token", authReqId);
    return body;
  }

  private static String requestId(Map<String, Object> response) {
    Object id = response.get("request_id");
    if (!(id instanceof String s) || s.isEmpty()) {
      throw new IllegalStateException("The authentication device returned no request_id.");
    }
    return s;
  }

  private Map<String, Object> post(String path, Map<String, Object> body, Duration timeout) {
    try {
      WSResponse response =
          ws.url(config.baseUrl() + path)
              .setRequestTimeout(timeout)
              .setContentType("application/json")
              .post(Jsons.write(body))
              .toCompletableFuture()
              .get(timeout.toMillis() + 5_000L, TimeUnit.MILLISECONDS);
      if (response.getStatus() / 100 != 2) {
        throw new IllegalStateException(
            "Authentication device responded " + response.getStatus() + " for " + path);
      }
      return Jsons.readMap(response.getBody());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("Interrupted while calling the authentication device", e);
    } catch (Exception e) {
      throw e instanceof IllegalStateException ise
          ? ise
          : new IllegalStateException("Authentication device call failed: " + e.getMessage(), e);
    }
  }
}

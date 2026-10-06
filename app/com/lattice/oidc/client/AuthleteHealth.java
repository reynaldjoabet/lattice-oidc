package com.lattice.oidc.client;

import com.authlete.common.api.AuthleteApi;
import java.util.Map;
import jakarta.inject.Inject;
import jakarta.inject.Provider;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Whether Authlete is usable: the client is configured and the service configuration can be
 * fetched. Used by the readiness probe and the operator console. Blocking: call it on the Authlete
 * execution context.
 */
@Singleton
public final class AuthleteHealth {

  private static final Logger LOG = LoggerFactory.getLogger(AuthleteHealth.class);

  private final Provider<AuthleteApi> api;

  @Inject
  public AuthleteHealth(Provider<AuthleteApi> api) {
    this.api = api;
  }

  /** {@code status} UP or DOWN, with a {@code reason} when DOWN. */
  public Map<String, String> check() {
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
}

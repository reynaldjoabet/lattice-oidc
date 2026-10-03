package com.lattice.oidc.client;

import com.typesafe.config.Config;
import java.time.Duration;
import java.util.Optional;

/** Typed, validated view of the {@code authlete} configuration section. */
public record AuthleteSettings(
    String baseUrl,
    long serviceId,
    String serviceAccessToken,
    Optional<String> dpopKey,
    Duration readTimeout,
    Duration connectTimeout) {

  /**
   * Reads and validates the configuration. Fails fast with a message naming the offending key, so a
   * misconfigured deployment does not start.
   */
  public static AuthleteSettings from(Config root) {
    Config c = root.getConfig("authlete");

    String baseUrl = c.getString("base-url").trim();
    if (!baseUrl.startsWith("https://") && !baseUrl.startsWith("http://")) {
      throw new IllegalStateException("authlete.base-url must be an http(s) URL: " + baseUrl);
    }
    String serviceIdValue = c.getString("service-id").trim();
    if (serviceIdValue.isEmpty()) {
      throw new IllegalStateException(
          "authlete.service-id is not set (environment variable AUTHLETE_SERVICE_APIKEY).");
    }
    long serviceId;
    try {
      serviceId = Long.parseLong(serviceIdValue);
    } catch (NumberFormatException e) {
      throw new IllegalStateException("authlete.service-id must be numeric: " + serviceIdValue, e);
    }
    String accessToken = c.getString("service-access-token").trim();
    if (accessToken.isEmpty()) {
      throw new IllegalStateException(
          "authlete.service-access-token is not set"
              + " (environment variable AUTHLETE_SERVICE_ACCESSTOKEN).");
    }
    String dpopKey = c.getString("dpop-key").trim();

    return new AuthleteSettings(
        baseUrl,
        serviceId,
        accessToken,
        dpopKey.isEmpty() ? Optional.empty() : Optional.of(dpopKey),
        c.getDuration("read-timeout"),
        root.getDuration("play.ws.timeout.connection"));
  }

  @Override
  public String toString() {
    // Never log credentials.
    return "AuthleteSettings[baseUrl="
        + baseUrl
        + ", serviceId="
        + serviceId
        + ", dpop="
        + dpopKey.isPresent()
        + ", readTimeout="
        + readTimeout
        + "]";
  }
}

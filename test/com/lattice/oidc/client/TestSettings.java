package com.lattice.oidc.client;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import java.util.Map;

/** Builds settings from the real application.conf with test overrides. */
public final class TestSettings {
  private TestSettings() {}

  public static Config config(Map<String, Object> overrides) {
    return ConfigFactory.parseMap(overrides)
        .withFallback(ConfigFactory.parseResources("application.conf"))
        .withFallback(ConfigFactory.defaultReference())
        .resolve();
  }

  public static AuthleteSettings settings(Map<String, Object> overrides) {
    Map<String, Object> base = new java.util.HashMap<>(overrides);
    base.putIfAbsent("authlete.service-id", "42");
    base.putIfAbsent("authlete.service-access-token", "token");
    return AuthleteSettings.from(config(base));
  }
}

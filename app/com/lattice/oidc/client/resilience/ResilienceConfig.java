package com.lattice.oidc.client.resilience;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;

/**
 * Settings of the Authlete resilience layer, from {@code authlete.resilience} in application.conf
 * (durations in HOCON's units); the getters return milliseconds.
 *
 * <p>The defaults bound retries to 3 attempts within 5 seconds, because a user's page waits on the
 * call and holds an Authlete thread, and don't cache introspection results (TTL 0), so a revoked
 * token never introspects as active on another replica.
 */
public final class ResilienceConfig {

  /** The defaults, as in application.conf; also used for anything a given config leaves out. */
  static final String DEFAULTS =
      """
      enabled = true
      cache {
        enabled = true
        ttl {
          service-configuration = 10 minutes
          service-jwks = 10 minutes
          client = 5 minutes
          credential-issuer-metadata = 10 minutes
          credential-issuer-jwks = 10 minutes
          introspection = 0
          standard-introspection = 0
        }
        stale = 30 minutes
        max-entries = 10000
      }
      retry {
        enabled = true
        max-attempts = 3
        base-delay = 500 milliseconds
        jitter = 200 milliseconds
        max-total = 5 seconds
      }
      breaker {
        enabled = true
        failure-threshold = 5
        window = 30 seconds
        open = 60 seconds
        half-open-trials = 1
      }
      """;

  private final Config c;

  /** The defaults. */
  public ResilienceConfig() {
    this(ConfigFactory.empty());
  }

  /** {@code resilience} is the {@code authlete.resilience} section; missing keys take the defaults. */
  public ResilienceConfig(Config resilience) {
    this.c = resilience.withFallback(ConfigFactory.parseString(DEFAULTS)).resolve();
  }

  private long millis(String path) {
    return c.getDuration(path).toMillis();
  }

  public boolean isEnabled() {
    return c.getBoolean("enabled");
  }

  public boolean isCacheEnabled() {
    return c.getBoolean("cache.enabled");
  }

  public long getCacheTtlServiceConfiguration() {
    return millis("cache.ttl.service-configuration");
  }

  public long getCacheTtlServiceJwks() {
    return millis("cache.ttl.service-jwks");
  }

  public long getCacheTtlClient() {
    return millis("cache.ttl.client");
  }

  public long getCacheTtlCredentialIssuerMetadata() {
    return millis("cache.ttl.credential-issuer-metadata");
  }

  public long getCacheTtlCredentialIssuerJwks() {
    return millis("cache.ttl.credential-issuer-jwks");
  }

  public long getCacheTtlIntrospection() {
    return millis("cache.ttl.introspection");
  }

  public long getCacheTtlStandardIntrospection() {
    return millis("cache.ttl.standard-introspection");
  }

  public long getCacheStaleMillis() {
    return millis("cache.stale");
  }

  public int getCacheMaxEntries() {
    return c.getInt("cache.max-entries");
  }

  public boolean isRetryEnabled() {
    return c.getBoolean("retry.enabled");
  }

  public int getRetryMaxAttempts() {
    return c.getInt("retry.max-attempts");
  }

  public long getRetryBaseDelayMillis() {
    return millis("retry.base-delay");
  }

  public long getRetryMaxTotalMillis() {
    return millis("retry.max-total");
  }

  public long getRetryJitterMillis() {
    return millis("retry.jitter");
  }

  public boolean isBreakerEnabled() {
    return c.getBoolean("breaker.enabled");
  }

  public int getBreakerFailureThreshold() {
    return c.getInt("breaker.failure-threshold");
  }

  public long getBreakerWindowMillis() {
    return millis("breaker.window");
  }

  public long getBreakerOpenMillis() {
    return millis("breaker.open");
  }

  public int getBreakerHalfOpenTrials() {
    return c.getInt("breaker.half-open-trials");
  }
}

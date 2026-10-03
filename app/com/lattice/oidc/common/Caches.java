package com.lattice.oidc.common;

/**
 * Names of the Caffeine caches bound in {@code play.cache.bindCaches}. Each kind of state has its
 * own size-bounded cache (configured under {@code play.cache.caffeine.caches}) so that one kind
 * cannot evict another. Inject with {@code @NamedCache(Caches.SESSIONS) SyncCacheApi}.
 */
public final class Caches {
  private Caches() {}

  public static final String SESSIONS = "lattice-sessions";
  public static final String INTERACTIONS = "lattice-interactions";
  public static final String LOGIN_FAILURES = "lattice-login-failures";
  public static final String DEVICE_SECRETS = "lattice-device-secrets";
  public static final String CIBA = "lattice-ciba";
  public static final String OBB_CONSENTS = "lattice-obb-consents";
}

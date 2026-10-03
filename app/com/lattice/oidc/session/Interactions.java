package com.lattice.oidc.session;

import com.lattice.oidc.config.LatticeConfig;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Singleton;
import play.cache.SyncCacheApi;

/**
 * Short-lived state of multi-step browser flows (authorization consent, device verification,
 * federation), bound to the browser that started them so another browser cannot complete them.
 */
@Singleton
public final class Interactions {

  private record Bound(String bid, Object value) {}

  private final SyncCacheApi cache;
  private final LatticeConfig config;

  @Inject
  public Interactions(SyncCacheApi cache, LatticeConfig config) {
    this.cache = cache;
    this.config = config;
  }

  public void put(String kind, String key, String bid, Object value) {
    cache.set(
        kind + ":" + key, new Bound(bid, value), (int) config.interactionTtl().toSeconds());
  }

  public <T> Optional<T> get(String kind, String key, String bid, Class<T> type) {
    if (key == null || bid == null) {
      return Optional.empty();
    }
    return cache.<Bound>get(kind + ":" + key)
        .filter(b -> b.bid().equals(bid))
        .map(Bound::value)
        .filter(type::isInstance)
        .map(type::cast);
  }

  /** Reads and removes the interaction (single use). */
  public <T> Optional<T> take(String kind, String key, String bid, Class<T> type) {
    Optional<T> value = get(kind, key, bid, type);
    value.ifPresent(v -> cache.remove(kind + ":" + key));
    return value;
  }
}

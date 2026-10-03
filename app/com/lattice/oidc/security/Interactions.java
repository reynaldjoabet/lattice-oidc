package com.lattice.oidc.security;

import com.lattice.oidc.common.Caches;
import com.lattice.oidc.common.LatticeConfig;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Singleton;
import play.cache.NamedCache;
import play.cache.SyncCacheApi;

/**
 * Short-lived state of multi-step browser flows (authorization consent, device verification,
 * federation), bound to the browser that started them so another browser cannot complete them.
 */
@Singleton
public final class Interactions {

  /** A stored value together with the id of the browser that started the flow. */
  private record Entry(String browserId, Object value) {}

  private final SyncCacheApi cache;
  private final LatticeConfig config;

  @Inject
  public Interactions(
      @NamedCache(Caches.INTERACTIONS) SyncCacheApi cache, LatticeConfig config) {
    this.cache = cache;
    this.config = config;
  }

  public void put(String kind, String key, String browserId, Object value) {
    cache.set(
        kind + ":" + key, new Entry(browserId, value), (int) config.interactionTtl().toSeconds());
  }

  public <T> Optional<T> get(String kind, String key, String browserId, Class<T> type) {
    if (key == null || browserId == null) {
      return Optional.empty();
    }
    return cache.<Entry>get(kind + ":" + key)
        .filter(entry -> entry.browserId().equals(browserId))
        .map(Entry::value)
        .filter(type::isInstance)
        .map(type::cast);
  }

  /** Reads and removes the interaction (single use). */
  public <T> Optional<T> take(String kind, String key, String browserId, Class<T> type) {
    Optional<T> value = get(kind, key, browserId, type);
    value.ifPresent(v -> cache.remove(kind + ":" + key));
    return value;
  }
}

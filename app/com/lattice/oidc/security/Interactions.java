package com.lattice.oidc.security;

import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.stores.EphemeralStore;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Singleton;

/**
 * Short-lived state of multi-step browser flows (authorization consent, device verification,
 * federation, passkey ceremonies), bound to the browser that started them so another browser cannot
 * complete them. Values are stored as JSON, so any server can continue a flow another one started.
 */
@Singleton
public final class Interactions {

  private final EphemeralStore store;
  private final LatticeConfig config;

  @Inject
  public Interactions(EphemeralStore store, LatticeConfig config) {
    this.store = store;
    this.config = config;
  }

  public void put(String kind, String key, String browserId, Object value) {
    store.put(namespace(kind), key, browserId, null, Jsons.write(value), config.interactionTtl());
  }

  public <T> Optional<T> get(String kind, String key, String browserId, Class<T> type) {
    if (key == null || browserId == null) {
      return Optional.empty();
    }
    return store.get(namespace(kind), key)
        .filter(entry -> browserId.equals(entry.owner()))
        .map(entry -> Jsons.read(entry.json(), type));
  }

  /** Reads and removes the interaction (single use: of two concurrent callers, only one gets it). */
  public <T> Optional<T> take(String kind, String key, String browserId, Class<T> type) {
    if (key == null || browserId == null || get(kind, key, browserId, type).isEmpty()) {
      return Optional.empty();
    }
    return store.take(namespace(kind), key)
        .filter(entry -> browserId.equals(entry.owner()))
        .map(entry -> Jsons.read(entry.json(), type));
  }

  private static String namespace(String kind) {
    return "interaction:" + kind;
  }
}

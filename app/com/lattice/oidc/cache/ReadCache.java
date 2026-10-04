package com.lattice.oidc.cache;

import java.util.Optional;

/**
 * A read cache in front of the stores ({@code lattice.cache}), for the lookups made on every
 * request: a user by subject and a session by id. Values are JSON. Entries live at most {@code
 * lattice.cache.ttl}, and every change to the underlying data invalidates them on every server, so a
 * sign-out, password change or removed passkey takes effect everywhere at once.
 *
 * <p>Single-use state (state, nonce, tickets, reset links) and counters are never cached: they rely
 * on one atomic step in their store, and a cached copy would allow reuse or under-counting.
 */
public interface ReadCache {

  Optional<String> get(String region, String key);

  void put(String region, String key, String json);

  /** Removes the entry here and, for a per-server cache, on every other server. */
  void invalidate(String region, String key);
}

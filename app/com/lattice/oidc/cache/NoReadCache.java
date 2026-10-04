package com.lattice.oidc.cache;

import java.util.Optional;
import javax.inject.Singleton;

/** {@code lattice.cache = none}: every lookup goes to the store. */
@Singleton
public final class NoReadCache implements ReadCache {

  @Override
  public Optional<String> get(String region, String key) {
    return Optional.empty();
  }

  @Override
  public void put(String region, String key, String json) {}

  @Override
  public void invalidate(String region, String key) {}
}

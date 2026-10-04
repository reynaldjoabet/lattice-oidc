package com.lattice.oidc.cache;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BiConsumer;
import javax.inject.Singleton;

/** {@link InvalidationBus} for one server ({@code lattice.storage = memory}): calls listeners directly. */
@Singleton
public final class LocalInvalidationBus implements InvalidationBus {

  private final List<BiConsumer<String, String>> listeners = new CopyOnWriteArrayList<>();

  @Override
  public void publish(String region, String key) {
    listeners.forEach(listener -> listener.accept(region, key));
  }

  @Override
  public void subscribe(BiConsumer<String, String> listener) {
    listeners.add(listener);
  }
}

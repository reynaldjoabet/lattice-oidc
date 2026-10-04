package com.lattice.oidc.cache;

import java.util.function.BiConsumer;

/** Tells every server that a cached entry changed, so per-server caches drop it. */
public interface InvalidationBus {

  /** Announces a change of {@code region}/{@code key} to every server, this one included. */
  void publish(String region, String key);

  /**
   * Registers what to do when a change is announced. {@code key} null means "anything may have
   * changed" (for example after missed announcements): drop everything.
   */
  void subscribe(BiConsumer<String, String> listener);
}

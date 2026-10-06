package com.lattice.oidc.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.lattice.oidc.metrics.Metrics;
import com.typesafe.config.Config;
import io.micrometer.core.instrument.binder.cache.CaffeineCacheMetrics;
import java.util.Optional;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/**
 * {@code lattice.cache = local}: a bounded cache in each server's memory (Caffeine). Changes are
 * announced on the {@link InvalidationBus}, so every server drops its copy; with PostgreSQL storage
 * the bus is PostgreSQL's {@code LISTEN}/{@code NOTIFY}.
 *
 * <p>One race remains, as with any invalidated cache: a server that read the old value just before a
 * change can store it just after the announcement. {@code lattice.cache.ttl} bounds how long that
 * stale copy can live.
 */
@Singleton
public final class LocalReadCache implements ReadCache {

  private final Cache<String, String> entries;
  private final InvalidationBus bus;

  @Inject
  public LocalReadCache(Config config, InvalidationBus bus, Metrics metrics) {
    this.entries =
        Caffeine.newBuilder()
            .maximumSize(config.getLong("lattice.cache.maximum-size"))
            .expireAfterWrite(config.getDuration("lattice.cache.ttl"))
            .recordStats()
            .build();
    // Size, evictions, hits and misses of the whole cache (cache="read_cache").
    CaffeineCacheMetrics.monitor(metrics.registry(), entries, "read_cache");
    this.bus = bus;
    bus.subscribe(
        (region, key) -> {
          if (key == null) {
            entries.invalidateAll();
          } else {
            entries.invalidate(entryKey(region, key));
          }
        });
  }

  @Override
  public Optional<String> get(String region, String key) {
    return Optional.ofNullable(entries.getIfPresent(entryKey(region, key)));
  }

  @Override
  public void put(String region, String key, String json) {
    entries.put(entryKey(region, key), json);
  }

  @Override
  public void invalidate(String region, String key) {
    entries.invalidate(entryKey(region, key));
    bus.publish(region, key);
  }

  private static String entryKey(String region, String key) {
    return region + ":" + key;
  }
}

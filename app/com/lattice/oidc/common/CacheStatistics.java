package com.lattice.oidc.common;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.stats.CacheStats;
import java.util.List;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Singleton;
import play.cache.NamedCacheImpl;
import play.cache.caffeine.NamedCaffeineCache;
import play.inject.BindingKey;
import play.inject.Injector;

/**
 * Size and hit statistics of the named Caffeine caches (statistics are on: {@code record-stats}),
 * for the operator console. Values are per node.
 */
@Singleton
public final class CacheStatistics {

  /** One cache: entries now, configured maximum, hit rate (0–1) and evictions since start. */
  public record Row(String name, long entries, Optional<Long> maximum, double hitRate, long evictions) {
    public String hitRatePercent() {
      return String.format("%.1f%%", hitRate * 100);
    }
  }

  private final Injector injector;

  @Inject
  public CacheStatistics(Injector injector) {
    this.injector = injector;
  }

  public List<Row> rows() {
    return Caches.ALL.stream().map(this::row).toList();
  }

  /** Approximate number of entries in one cache. */
  public long entries(String name) {
    return cache(name).estimatedSize();
  }

  private Row row(String name) {
    Cache<?, ?> cache = cache(name);
    CacheStats stats = cache.stats();
    Optional<Long> maximum = cache.policy().eviction().map(eviction -> eviction.getMaximum());
    return new Row(name, cache.estimatedSize(), maximum, stats.hitRate(), stats.evictionCount());
  }

  @SuppressWarnings("rawtypes")
  private Cache<?, ?> cache(String name) {
    NamedCaffeineCache named =
        injector.instanceOf(
            new BindingKey<>(NamedCaffeineCache.class).qualifiedWith(new NamedCacheImpl(name)).asScala());
    return named.synchronous();
  }
}

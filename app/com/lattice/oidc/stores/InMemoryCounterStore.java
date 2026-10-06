package com.lattice.oidc.stores;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.inject.Singleton;

/** {@link CounterStore} in memory, for one server (development and tests). */
@Singleton
public final class InMemoryCounterStore implements CounterStore {

  private record Counter(long count, Instant windowEndsAt) {}

  private final Map<String, Counter> counters = new ConcurrentHashMap<>();

  @Override
  public long increment(String key, Duration window) {
    Instant now = Instant.now();
    return counters
        .compute(
            key,
            (ignored, existing) ->
                existing == null || !existing.windowEndsAt().isAfter(now)
                    ? new Counter(1, now.plus(window))
                    : new Counter(existing.count() + 1, existing.windowEndsAt()))
        .count();
  }

  @Override
  public long count(String key) {
    Counter counter = counters.get(key);
    return counter == null || !counter.windowEndsAt().isAfter(Instant.now()) ? 0 : counter.count();
  }

  @Override
  public void reset(String key) {
    counters.remove(key);
  }

  @Override
  public void resetPrefix(String prefix) {
    counters.keySet().removeIf(key -> key.startsWith(prefix));
  }

  @Override
  public long countAtLeast(String prefix, long minimum) {
    Instant now = Instant.now();
    counters.values().removeIf(counter -> !counter.windowEndsAt().isAfter(now));
    return counters.entrySet().stream()
        .filter(entry -> entry.getKey().startsWith(prefix) && entry.getValue().count() >= minimum)
        .count();
  }
}

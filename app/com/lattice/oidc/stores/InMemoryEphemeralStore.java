package com.lattice.oidc.stores;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import jakarta.inject.Singleton;

/**
 * {@link EphemeralStore} in memory, for one server. Each namespace holds at most {@link
 * #MAX_PER_NAMESPACE} entries, so flooding one kind of state (for example pending sign-ins) cannot
 * push out another (for example reset links); when full, the entry closest to expiry goes first.
 */
@Singleton
public final class InMemoryEphemeralStore implements EphemeralStore {

  static final int MAX_PER_NAMESPACE = 50_000;

  private final Map<String, Map<String, Entry>> namespaces = new ConcurrentHashMap<>();
  private final int maxPerNamespace;

  public InMemoryEphemeralStore() {
    this(MAX_PER_NAMESPACE);
  }

  InMemoryEphemeralStore(int maxPerNamespace) {
    this.maxPerNamespace = maxPerNamespace;
  }

  private Map<String, Entry> namespace(String name) {
    return namespaces.computeIfAbsent(name, ignored -> new ConcurrentHashMap<>());
  }

  private static boolean live(Entry entry) {
    return entry.expiresAt().isAfter(Instant.now());
  }

  @Override
  public void put(String namespace, String key, String owner, String subject, String json, Duration ttl) {
    Map<String, Entry> entries = namespace(namespace);
    entries.put(key, new Entry(namespace, key, owner, subject, json, Instant.now().plus(ttl)));
    if (entries.size() > maxPerNamespace) {
      evict(entries, maxPerNamespace);
    }
  }

  /** Set while one thread is evicting: the others carry on, and the cap holds again a moment later. */
  private final AtomicBoolean evicting = new AtomicBoolean();

  /**
   * Brings a namespace that went over its cap back under it: first the expired entries, then, if
   * the rest are all live, the ones expiring soonest, <b>down to 90% of the cap in one pass</b>.
   *
   * <p>Making room for one entry at a time was a flaw. Once a namespace was full, every {@code put}
   * scanned all of it to find the oldest entry, under a lock shared by the whole JVM: a flood of
   * authorization requests (or a load test) made every later request pay a scan of 50,000 entries,
   * one thread at a time. Evicting a tenth of the cap per pass spreads one scan over thousands of
   * puts, and a thread that finds another already evicting just continues.
   */
  private void evict(Map<String, Entry> entries, int max) {
    if (!evicting.compareAndSet(false, true)) {
      return;
    }
    try {
      Instant now = Instant.now();
      entries.values().removeIf(entry -> !entry.expiresAt().isAfter(now));
      int target = max - Math.max(1, max / 10);
      int excess = entries.size() - target;
      if (entries.size() <= max || excess <= 0) {
        return;
      }
      entries.values().stream()
          .sorted(Comparator.comparing(Entry::expiresAt))
          .limit(excess)
          .toList()
          .forEach(oldest -> entries.remove(oldest.key(), oldest));
    } finally {
      evicting.set(false);
    }
  }

  @Override
  public Optional<Entry> get(String namespace, String key) {
    if (key == null) {
      return Optional.empty();
    }
    return Optional.ofNullable(namespace(namespace).get(key)).filter(InMemoryEphemeralStore::live);
  }

  @Override
  public Optional<Entry> take(String namespace, String key) {
    if (key == null) {
      return Optional.empty();
    }
    return Optional.ofNullable(namespace(namespace).remove(key)).filter(InMemoryEphemeralStore::live);
  }

  @Override
  public List<Entry> bySubject(String namespace, String subject) {
    return namespace(namespace).values().stream()
        .filter(entry -> subject != null && subject.equals(entry.subject()) && live(entry))
        .sorted(Comparator.comparing(Entry::expiresAt))
        .toList();
  }

  @Override
  public void delete(String namespace, String key) {
    if (key != null) {
      namespace(namespace).remove(key);
    }
  }

  @Override
  public int deleteBySubject(String namespace, String subject) {
    Map<String, Entry> entries = namespace(namespace);
    int[] removed = {0};
    entries.values().removeIf(
        entry -> {
          boolean match = subject != null && subject.equals(entry.subject());
          if (match) {
            removed[0]++;
          }
          return match;
        });
    return removed[0];
  }

  @Override
  public long count(String namespace) {
    return namespace(namespace).values().stream().filter(InMemoryEphemeralStore::live).count();
  }

  @Override
  public Map<String, Long> counts() {
    Map<String, Long> counts = new java.util.TreeMap<>();
    namespaces.keySet().forEach(name -> counts.put(name, count(name)));
    return counts;
  }
}

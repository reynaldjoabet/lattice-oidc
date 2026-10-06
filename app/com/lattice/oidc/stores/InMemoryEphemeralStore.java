package com.lattice.oidc.stores;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
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

  private static synchronized void evict(Map<String, Entry> entries, int max) {
    entries.values().removeIf(entry -> !live(entry));
    while (entries.size() > max) {
      entries.values().stream()
          .min(Comparator.comparing(Entry::expiresAt))
          .ifPresent(oldest -> entries.remove(oldest.key()));
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

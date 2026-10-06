package com.lattice.oidc.stores.redis;

import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.stores.EphemeralStore;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import redis.clients.jedis.params.ScanParams;
import redis.clients.jedis.params.SetParams;
import redis.clients.jedis.resps.ScanResult;

/**
 * {@link EphemeralStore} in Redis ({@code lattice.short-lived-state = redis}). Each entry is a key
 * that Redis expires on its own; single use is {@code GETDEL}, which only one caller can win. Entries
 * indexed by account are also listed in a sorted set per account, scored by expiry time.
 */
@Singleton
public final class RedisEphemeralStore implements EphemeralStore {

  /** What is stored under an entry's key. */
  private record Stored(String owner, String subject, String json, Instant expiresAt) {}

  /** Extends a key's expiry to at least ARGV[1] milliseconds, never shortens it. */
  private static final String EXTEND =
      "local remaining = redis.call('PTTL', KEYS[1]) "
          + "if remaining < tonumber(ARGV[1]) then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end "
          + "return 1";

  private final RedisConnection redis;

  @Inject
  public RedisEphemeralStore(RedisConnection redis) {
    this.redis = redis;
  }

  private String entryKey(String namespace, String key) {
    return redis.key("eph", namespace, key);
  }

  private String subjectKey(String namespace, String subject) {
    return redis.key("eph-subject", namespace, subject);
  }

  private static Entry entry(String namespace, String key, String value) {
    Stored stored = Jsons.read(value, Stored.class);
    return new Entry(namespace, key, stored.owner(), stored.subject(), stored.json(), stored.expiresAt());
  }

  @Override
  public void put(String namespace, String key, String owner, String subject, String json, Duration ttl) {
    Instant expiresAt = Instant.now().plus(ttl);
    redis.client()
        .set(
            entryKey(namespace, key),
            Jsons.write(new Stored(owner, subject, json, expiresAt)),
            SetParams.setParams().px(Math.max(1, ttl.toMillis())));
    if (subject != null) {
      String index = subjectKey(namespace, subject);
      redis.client().zadd(index, expiresAt.toEpochMilli(), key);
      // The index lives as long as its longest-lived entry.
      redis.client().eval(EXTEND, List.of(index), List.of(String.valueOf(Math.max(1, ttl.toMillis()))));
    }
  }

  @Override
  public Optional<Entry> get(String namespace, String key) {
    if (key == null) {
      return Optional.empty();
    }
    return Optional.ofNullable(redis.client().get(entryKey(namespace, key))).map(value -> entry(namespace, key, value));
  }

  @Override
  public Optional<Entry> take(String namespace, String key) {
    if (key == null) {
      return Optional.empty();
    }
    Optional<Entry> taken =
        Optional.ofNullable(redis.client().getDel(entryKey(namespace, key))).map(value -> entry(namespace, key, value));
    taken.filter(entry -> entry.subject() != null)
        .ifPresent(entry -> redis.client().zrem(subjectKey(namespace, entry.subject()), key));
    return taken;
  }

  @Override
  public List<Entry> bySubject(String namespace, String subject) {
    String index = subjectKey(namespace, subject);
    long now = Instant.now().toEpochMilli();
    redis.client().zremrangeByScore(index, Double.NEGATIVE_INFINITY, now);
    List<String> keys = redis.client().zrangeByScore(index, now, Double.POSITIVE_INFINITY);
    if (keys.isEmpty()) {
      return List.of();
    }
    List<String> values = redis.client().mget(keys.stream().map(key -> entryKey(namespace, key)).toArray(String[]::new));
    List<Entry> entries = new ArrayList<>();
    for (int i = 0; i < keys.size(); i++) {
      if (values.get(i) != null) {
        entries.add(entry(namespace, keys.get(i), values.get(i)));
      }
    }
    return entries;
  }

  @Override
  public void delete(String namespace, String key) {
    take(namespace, key);
  }

  @Override
  public int deleteBySubject(String namespace, String subject) {
    List<Entry> entries = bySubject(namespace, subject);
    if (!entries.isEmpty()) {
      redis.client().del(entries.stream().map(entry -> entryKey(namespace, entry.key())).toArray(String[]::new));
    }
    redis.client().del(subjectKey(namespace, subject));
    return entries.size();
  }

  @Override
  public long count(String namespace) {
    return counts().getOrDefault(namespace, 0L);
  }

  /** Scans every entry key: fine for the operator console, not for request paths. */
  @Override
  public Map<String, Long> counts() {
    Map<String, Long> counts = new TreeMap<>();
    String prefix = redis.key("eph") + ":";
    ScanParams params = new ScanParams().match(prefix + "*").count(1_000);
    String cursor = ScanParams.SCAN_POINTER_START;
    do {
      ScanResult<String> page = redis.client().scan(cursor, params);
      for (String key : page.getResult()) {
        String rest = key.substring(prefix.length());
        int end = rest.lastIndexOf(':');
        // Namespaces may contain ':' (for example "interaction:authz"); keys never do.
        counts.merge(end > 0 ? rest.substring(0, end) : rest, 1L, Long::sum);
      }
      cursor = page.getCursor();
    } while (!cursor.equals(ScanParams.SCAN_POINTER_START));
    return counts;
  }
}

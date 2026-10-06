package com.lattice.oidc.stores.redis;

import com.lattice.oidc.stores.CounterStore;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import redis.clients.jedis.params.ScanParams;
import redis.clients.jedis.resps.ScanResult;

/**
 * {@link CounterStore} in Redis ({@code lattice.short-lived-state = redis}). A counter is a key that
 * expires when its window ends; incrementing is one script, so concurrent increments on any server
 * all count and the window starts with the first one.
 */
@Singleton
public final class RedisCounterStore implements CounterStore {

  private static final String INCREMENT =
      "local count = redis.call('INCR', KEYS[1]) "
          + "if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end "
          + "return count";

  private final RedisConnection redis;

  @Inject
  public RedisCounterStore(RedisConnection redis) {
    this.redis = redis;
  }

  private String counterKey(String key) {
    return redis.key("counter", key);
  }

  @Override
  public long increment(String key, Duration window) {
    Object count =
        redis.client()
            .eval(INCREMENT, List.of(counterKey(key)), List.of(String.valueOf(Math.max(1, window.toMillis()))));
    return ((Number) count).longValue();
  }

  @Override
  public long count(String key) {
    String value = redis.client().get(counterKey(key));
    return value == null ? 0 : Long.parseLong(value);
  }

  @Override
  public void reset(String key) {
    redis.client().del(counterKey(key));
  }

  @Override
  public void resetPrefix(String prefix) {
    List<String> keys = scan(prefix);
    if (!keys.isEmpty()) {
      redis.client().del(keys.toArray(String[]::new));
    }
  }

  @Override
  public long countAtLeast(String prefix, long minimum) {
    List<String> keys = scan(prefix);
    if (keys.isEmpty()) {
      return 0;
    }
    return redis.client().mget(keys.toArray(String[]::new)).stream()
        .filter(value -> value != null && Long.parseLong(value) >= minimum)
        .count();
  }

  /** Keys of counters starting with {@code prefix}. Glob characters in it are escaped. */
  private List<String> scan(String prefix) {
    String pattern = counterKey(prefix).replaceAll("([*?\\[\\]\\\\])", "\\\\$1") + "*";
    ScanParams params = new ScanParams().match(pattern).count(1_000);
    List<String> keys = new ArrayList<>();
    String cursor = ScanParams.SCAN_POINTER_START;
    do {
      ScanResult<String> page = redis.client().scan(cursor, params);
      keys.addAll(page.getResult());
      cursor = page.getCursor();
    } while (!cursor.equals(ScanParams.SCAN_POINTER_START));
    return keys;
  }
}

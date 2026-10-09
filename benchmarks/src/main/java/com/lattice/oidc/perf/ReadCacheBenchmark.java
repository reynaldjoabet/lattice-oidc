package com.lattice.oidc.perf;

import com.lattice.oidc.cache.CachingUserStore;
import com.lattice.oidc.cache.LocalInvalidationBus;
import com.lattice.oidc.cache.LocalReadCache;
import com.lattice.oidc.metrics.Metrics;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.UserStore;
import com.typesafe.config.ConfigFactory;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

/**
 * The user lookup made on every signed-in request, with and without the in-memory read cache. The
 * backing store here is a hash map, so it is the floor: the cache stores values as JSON, and a hit
 * costs the deserialisation. What it saves is the cost of a real store (PostgreSQL: a network round
 * trip), not a map lookup. Measure that with a PostgreSQL-backed load test.
 */
@Fork(2)
@Warmup(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class ReadCacheBenchmark {

  /** Account lookups from a map, for the cheapest possible store. */
  private static final class MapUserStore implements UserStore {
    final Map<String, User> users = new ConcurrentHashMap<>();

    @Override
    public Optional<User> bySubject(String subject) {
      return Optional.ofNullable(users.get(subject));
    }

    @Override
    public Optional<User> byLoginId(String loginId) {
      return Optional.empty();
    }

    @Override
    public Optional<User> byEmail(String email) {
      return Optional.empty();
    }

    @Override
    public Optional<User> byPhoneNumber(String phoneNumber) {
      return Optional.empty();
    }

    @Override
    public void save(User user) {
      users.put(user.getSubject(), user);
    }
  }

  private MapUserStore backing;
  private UserStore cached;
  private User user;

  @Setup
  public void stores() {
    Metrics metrics = new Metrics(new play.inject.DelegateApplicationLifecycle(new play.api.inject.DefaultApplicationLifecycle()));
    backing = new MapUserStore();
    user =
        new User(
            "1001", "john", "$argon2id$v=19$m=15360,t=2,p=1$placeholder",
            Map.of("name", "John Flibble Smith", "email", "john@example.com", "email_verified", true),
            Map.of("requiredActions", List.of()), List.of());
    backing.save(user);
    cached =
        new CachingUserStore(
            backing,
            new LocalReadCache(
                ConfigFactory.parseMap(Map.of("lattice.cache.ttl", "10 minutes", "lattice.cache.maximum-size", 100_000)),
                new LocalInvalidationBus(),
                metrics),
            metrics);
    cached.bySubject("1001"); // warm
  }

  @Benchmark
  public Optional<User> directMapLookup() {
    return backing.bySubject("1001");
  }

  @Benchmark
  public Optional<User> cachedLookup() {
    return cached.bySubject("1001");
  }

  /** A change: writes the store and announces the invalidation (the next lookup misses). */
  @Benchmark
  public void saveAndInvalidate() {
    cached.save(user);
  }
}

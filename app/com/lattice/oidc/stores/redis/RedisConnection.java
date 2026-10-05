package com.lattice.oidc.stores.redis;

import com.lattice.oidc.metrics.Metrics;
import com.typesafe.config.Config;
import io.micrometer.core.instrument.Gauge;
import java.net.URI;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.inject.ApplicationLifecycle;
import redis.clients.jedis.CommandObject;
import redis.clients.jedis.Connection;
import redis.clients.jedis.RedisClient;
import redis.clients.jedis.executors.CommandExecutor;
import redis.clients.jedis.util.Pool;

/**
 * The pooled Redis client ({@code lattice.redis.url}, for example {@code redis://:password@host:6379}
 * or {@code rediss://} for TLS). It is checked with a PING at startup, so a wrong address stops the
 * server at startup instead of the first sign-in. All keys start with {@code lattice.redis.key-prefix},
 * so one Redis can serve several deployments.
 */
@Singleton
public final class RedisConnection {

  private static final Logger LOG = LoggerFactory.getLogger(RedisConnection.class);

  private final RedisClient client;
  private final String prefix;

  @Inject
  public RedisConnection(Config config, ApplicationLifecycle lifecycle, Metrics metrics) {
    // Every command goes through one executor; wrapping it times them all (lattice_redis_commands).
    this.client =
        new RedisClient.Builder() {
          @Override
          protected CommandExecutor createDefaultCommandExecutor() {
            return new TimedCommandExecutor(super.createDefaultCommandExecutor(), metrics);
          }
        }.fromURI(URI.create(config.getString("lattice.redis.url"))).build();
    this.prefix = config.getString("lattice.redis.key-prefix");
    Pool<Connection> pool = client.getPool();
    Gauge.builder("lattice.redis.connections", pool, Pool::getNumActive)
        .description("Redis connections")
        .tag("state", "active")
        .register(metrics.registry());
    Gauge.builder("lattice.redis.connections", pool, Pool::getNumIdle)
        .description("Redis connections")
        .tag("state", "idle")
        .register(metrics.registry());
    Gauge.builder("lattice.redis.connections.waiting", pool, Pool::getNumWaiters)
        .description("Threads waiting for a Redis connection")
        .register(metrics.registry());
    lifecycle.addStopHook(
        () -> {
          client.close();
          return CompletableFuture.completedFuture(null);
        });
    client.ping();
    LOG.info("Redis ready (key prefix \"{}\")", prefix);
  }

  /** Times each command by its name (GET, SET, EVAL, ...) and outcome. */
  private static final class TimedCommandExecutor implements CommandExecutor {
    private final CommandExecutor delegate;
    private final Metrics metrics;

    TimedCommandExecutor(CommandExecutor delegate, Metrics metrics) {
      this.delegate = delegate;
      this.metrics = metrics;
    }

    @Override
    public <T> T executeCommand(CommandObject<T> command) {
      long started = System.nanoTime();
      boolean success = false;
      try {
        T result = delegate.executeCommand(command);
        success = true;
        return result;
      } finally {
        metrics.redisCommand(name(command), success, Duration.ofNanos(System.nanoTime() - started));
      }
    }

    /** Jedis's own command names; anything else is "OTHER", so the tag stays bounded. */
    private static String name(CommandObject<?> command) {
      return command.getArguments().getCommand() instanceof Enum<?> known ? known.name() : "OTHER";
    }

    @Override
    public void close() throws Exception {
      delegate.close();
    }
  }

  public RedisClient client() {
    return client;
  }

  /** The full key for {@code parts}, joined with ':' after the deployment prefix. */
  public String key(String... parts) {
    return prefix + String.join(":", parts);
  }

  /** The key prefix of this deployment (to strip it from scanned keys). */
  public String prefix() {
    return prefix;
  }
}

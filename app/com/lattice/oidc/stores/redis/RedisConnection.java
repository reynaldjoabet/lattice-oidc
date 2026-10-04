package com.lattice.oidc.stores.redis;

import com.typesafe.config.Config;
import java.net.URI;
import java.util.concurrent.CompletableFuture;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.inject.ApplicationLifecycle;
import redis.clients.jedis.RedisClient;

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
  public RedisConnection(Config config, ApplicationLifecycle lifecycle) {
    this.client = RedisClient.create(URI.create(config.getString("lattice.redis.url")));
    this.prefix = config.getString("lattice.redis.key-prefix");
    lifecycle.addStopHook(
        () -> {
          client.close();
          return CompletableFuture.completedFuture(null);
        });
    client.ping();
    LOG.info("Redis ready (key prefix \"{}\")", prefix);
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

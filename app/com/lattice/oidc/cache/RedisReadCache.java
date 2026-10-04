package com.lattice.oidc.cache;

import com.lattice.oidc.stores.redis.RedisConnection;
import com.typesafe.config.Config;
import java.time.Duration;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Singleton;
import redis.clients.jedis.params.SetParams;

/**
 * {@code lattice.cache = redis}: one cache shared by every server, so invalidating it is simply
 * deleting the entry. Entries expire after {@code lattice.cache.ttl}.
 */
@Singleton
public final class RedisReadCache implements ReadCache {

  private final RedisConnection redis;
  private final Duration ttl;

  @Inject
  public RedisReadCache(RedisConnection redis, Config config) {
    this.redis = redis;
    this.ttl = config.getDuration("lattice.cache.ttl");
  }

  @Override
  public Optional<String> get(String region, String key) {
    return Optional.ofNullable(redis.client().get(redis.key("cache", region, key)));
  }

  @Override
  public void put(String region, String key, String json) {
    redis.client().set(redis.key("cache", region, key), json, SetParams.setParams().px(ttl.toMillis()));
  }

  @Override
  public void invalidate(String region, String key) {
    redis.client().del(redis.key("cache", region, key));
  }
}

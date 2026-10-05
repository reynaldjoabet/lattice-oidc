package com.lattice.oidc.modules;

import com.google.inject.AbstractModule;
import com.google.inject.name.Names;
import com.lattice.oidc.cache.CachingSessionStore;
import com.lattice.oidc.cache.CachingUserStore;
import com.lattice.oidc.cache.InvalidationBus;
import com.lattice.oidc.cache.LocalInvalidationBus;
import com.lattice.oidc.cache.LocalReadCache;
import com.lattice.oidc.cache.PostgresInvalidationBus;
import com.lattice.oidc.cache.ReadCache;
import com.lattice.oidc.cache.RedisReadCache;
import com.lattice.oidc.metrics.SessionGauge;
import com.lattice.oidc.stores.AuditEventStore;
import com.lattice.oidc.stores.ConsentStore;
import com.lattice.oidc.stores.CounterStore;
import com.lattice.oidc.stores.EphemeralStore;
import com.lattice.oidc.stores.IdentityLinkStore;
import com.lattice.oidc.stores.InMemoryAuditEventStore;
import com.lattice.oidc.stores.InMemoryConsentStore;
import com.lattice.oidc.stores.InMemoryCounterStore;
import com.lattice.oidc.stores.InMemoryEphemeralStore;
import com.lattice.oidc.stores.InMemoryIdentityLinkStore;
import com.lattice.oidc.stores.InMemoryPasskeyStore;
import com.lattice.oidc.stores.InMemorySecondFactorStore;
import com.lattice.oidc.stores.InMemorySessionStore;
import com.lattice.oidc.stores.InMemoryUserStore;
import com.lattice.oidc.stores.PasskeyStore;
import com.lattice.oidc.stores.SecondFactorStore;
import com.lattice.oidc.stores.SessionStore;
import com.lattice.oidc.stores.UserStore;
import com.lattice.oidc.stores.postgres.PostgresAuditEventStore;
import com.lattice.oidc.stores.postgres.PostgresConsentStore;
import com.lattice.oidc.stores.postgres.PostgresCounterStore;
import com.lattice.oidc.stores.postgres.PostgresDatabase;
import com.lattice.oidc.stores.postgres.PostgresEphemeralStore;
import com.lattice.oidc.stores.postgres.PostgresIdentityLinkStore;
import com.lattice.oidc.stores.postgres.PostgresPasskeyStore;
import com.lattice.oidc.stores.postgres.PostgresSecondFactorStore;
import com.lattice.oidc.stores.postgres.PostgresSessionStore;
import com.lattice.oidc.stores.postgres.PostgresUserStore;
import com.lattice.oidc.stores.postgres.StorageCleanup;
import com.lattice.oidc.stores.redis.RedisConnection;
import com.lattice.oidc.stores.redis.RedisCounterStore;
import com.lattice.oidc.stores.redis.RedisEphemeralStore;
import com.typesafe.config.Config;
import java.util.Locale;
import play.Environment;

/**
 * Chooses where state is kept, from three independent settings:
 *
 * <ul>
 *   <li>{@code lattice.storage} ("memory" or "postgres"): accounts, passkeys, links, consents and
 *       sessions.
 *   <li>{@code lattice.short-lived-state} ("storage" or "redis"): single-use state and counters.
 *   <li>{@code lattice.cache.type} ("none", "local" or "redis"): a read cache in front of the user and
 *       session stores.
 * </ul>
 *
 * PostgreSQL and Redis are connected at startup, so a wrong address or password fails the
 * deployment instead of the first sign-in.
 */
public final class StorageModule extends AbstractModule {

  private final Config config;

  public StorageModule(Environment environment, Config config) {
    this.config = config;
  }

  private String setting(String path, String... allowed) {
    String value = config.getString(path).trim().toLowerCase(Locale.ROOT);
    for (String option : allowed) {
      if (option.equals(value)) {
        return value;
      }
    }
    throw new IllegalArgumentException(
        path + " must be one of " + String.join(", ", allowed) + ", not \"" + value + "\"");
  }

  @Override
  protected void configure() {
    boolean postgres = setting("lattice.storage", "memory", "postgres").equals("postgres");
    boolean redisState = setting("lattice.short-lived-state", "storage", "redis").equals("redis");
    String cache = setting("lattice.cache.type", "none", "local", "redis");
    if (redisState || cache.equals("redis")) {
      bind(RedisConnection.class).asEagerSingleton();
    }
    bind(SessionGauge.class).asEagerSingleton();
    if (config.getBoolean("lattice.ldap.enabled")) {
      // Connect at startup, so a wrong directory address or bind password fails the deployment.
      bind(com.lattice.oidc.security.LdapDirectory.class).asEagerSingleton();
    }

    // Durable data.
    if (postgres) {
      bind(PostgresDatabase.class).asEagerSingleton();
      bind(StorageCleanup.class).asEagerSingleton();
      bind(PasskeyStore.class).to(PostgresPasskeyStore.class);
      bind(IdentityLinkStore.class).to(PostgresIdentityLinkStore.class);
      bind(ConsentStore.class).to(PostgresConsentStore.class);
      bind(AuditEventStore.class).to(PostgresAuditEventStore.class);
      bind(SecondFactorStore.class).to(PostgresSecondFactorStore.class);
    } else {
      bind(PasskeyStore.class).to(InMemoryPasskeyStore.class);
      bind(IdentityLinkStore.class).to(InMemoryIdentityLinkStore.class);
      bind(ConsentStore.class).to(InMemoryConsentStore.class);
      bind(AuditEventStore.class).to(InMemoryAuditEventStore.class);
      bind(SecondFactorStore.class).to(InMemorySecondFactorStore.class);
    }

    // Users and sessions, with or without the read cache in front.
    Class<? extends UserStore> users = postgres ? PostgresUserStore.class : InMemoryUserStore.class;
    Class<? extends SessionStore> sessions = postgres ? PostgresSessionStore.class : InMemorySessionStore.class;
    if (cache.equals("none")) {
      bind(UserStore.class).to(users);
      bind(SessionStore.class).to(sessions);
    } else {
      bind(UserStore.class).annotatedWith(Names.named("backing")).to(users);
      bind(SessionStore.class).annotatedWith(Names.named("backing")).to(sessions);
      bind(UserStore.class).to(CachingUserStore.class);
      bind(SessionStore.class).to(CachingSessionStore.class);
      if (cache.equals("redis")) {
        bind(ReadCache.class).to(RedisReadCache.class);
      } else {
        bind(ReadCache.class).to(LocalReadCache.class);
        // Several servers only share data through PostgreSQL, so that's where changes are announced.
        bind(InvalidationBus.class).to(postgres ? PostgresInvalidationBus.class : LocalInvalidationBus.class);
      }
    }

    // Single-use state and counters.
    if (redisState) {
      bind(EphemeralStore.class).to(RedisEphemeralStore.class);
      bind(CounterStore.class).to(RedisCounterStore.class);
    } else if (postgres) {
      bind(EphemeralStore.class).to(PostgresEphemeralStore.class);
      bind(CounterStore.class).to(PostgresCounterStore.class);
    } else {
      bind(EphemeralStore.class).to(InMemoryEphemeralStore.class);
      bind(CounterStore.class).to(InMemoryCounterStore.class);
    }
  }
}

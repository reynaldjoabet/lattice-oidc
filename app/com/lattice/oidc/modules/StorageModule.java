package com.lattice.oidc.modules;

import com.google.inject.AbstractModule;
import com.lattice.oidc.stores.ConsentStore;
import com.lattice.oidc.stores.CounterStore;
import com.lattice.oidc.stores.EphemeralStore;
import com.lattice.oidc.stores.IdentityLinkStore;
import com.lattice.oidc.stores.PasskeyStore;
import com.lattice.oidc.stores.SessionStore;
import com.lattice.oidc.stores.UserStore;
import com.lattice.oidc.stores.postgres.PostgresConsentStore;
import com.lattice.oidc.stores.postgres.PostgresCounterStore;
import com.lattice.oidc.stores.postgres.PostgresDatabase;
import com.lattice.oidc.stores.postgres.PostgresEphemeralStore;
import com.lattice.oidc.stores.postgres.PostgresIdentityLinkStore;
import com.lattice.oidc.stores.postgres.PostgresPasskeyStore;
import com.lattice.oidc.stores.postgres.PostgresSessionStore;
import com.lattice.oidc.stores.postgres.PostgresUserStore;
import com.lattice.oidc.stores.postgres.StorageCleanup;
import com.typesafe.config.Config;
import java.util.Locale;
import play.Environment;

/**
 * Chooses where state is kept ({@code lattice.storage}). With "memory" nothing is bound here and
 * every store uses its in-memory default ({@code @ImplementedBy}). With "postgres" every store uses
 * PostgreSQL; the database is connected and migrated at startup, so a wrong URL or password fails
 * the deployment instead of the first sign-in.
 */
public final class StorageModule extends AbstractModule {

  private final Config config;

  public StorageModule(Environment environment, Config config) {
    this.config = config;
  }

  @Override
  protected void configure() {
    String storage = config.getString("lattice.storage").trim().toLowerCase(Locale.ROOT);
    switch (storage) {
      case "memory" -> {
        // In-memory defaults.
      }
      case "postgres" -> {
        bind(PostgresDatabase.class).asEagerSingleton();
        bind(UserStore.class).to(PostgresUserStore.class);
        bind(PasskeyStore.class).to(PostgresPasskeyStore.class);
        bind(IdentityLinkStore.class).to(PostgresIdentityLinkStore.class);
        bind(ConsentStore.class).to(PostgresConsentStore.class);
        bind(SessionStore.class).to(PostgresSessionStore.class);
        bind(EphemeralStore.class).to(PostgresEphemeralStore.class);
        bind(CounterStore.class).to(PostgresCounterStore.class);
        bind(StorageCleanup.class).asEagerSingleton();
      }
      default -> throw new IllegalArgumentException(
          "lattice.storage must be \"memory\" or \"postgres\", not \"" + storage + "\"");
    }
  }
}

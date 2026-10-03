package com.lattice.oidc.client;

import com.authlete.common.api.AuthleteApi;
import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import com.typesafe.config.Config;
import javax.inject.Singleton;
import play.Environment;

/**
 * Wires the Authlete client. In production the settings are validated at startup so a missing
 * credential fails the deployment instead of the first login; elsewhere they are loaded lazily so
 * the app and tests can start without Authlete credentials.
 */
public final class AuthleteModule extends AbstractModule {

  private final Environment environment;
  private final Config config;

  public AuthleteModule(Environment environment, Config config) {
    this.environment = environment;
    this.config = config;
  }

  @Override
  protected void configure() {
    if (environment.isProd()) {
      AuthleteSettings.from(config); // Fail fast on misconfiguration.
      bind(AuthleteApi.class).toProvider(AuthleteApiProvider.class).asEagerSingleton();
    } else {
      bind(AuthleteApi.class).toProvider(AuthleteApiProvider.class).in(Singleton.class);
    }
  }

  @Provides
  @Singleton
  AuthleteSettings settings() {
    return AuthleteSettings.from(config);
  }
}

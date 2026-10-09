package com.lattice.oidc.client;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.conf.AuthleteSimpleConfiguration;
import com.lattice.oidc.metrics.MeteredAuthleteApi;
import com.lattice.oidc.metrics.Metrics;
import com.lattice.oidc.client.resilience.ResilienceConfig;
import com.lattice.oidc.client.resilience.ResilientAuthleteApi;
import com.typesafe.config.Config;
import io.micrometer.core.instrument.Gauge;
import jakarta.inject.Inject;
import jakarta.inject.Provider;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.libs.ws.WSClient;

/**
 * Builds the process-wide Authlete client: on the Play WS transport, with every HTTP call timed,
 * behind the resilience layer ({@code authlete.resilience}): caching with stale fallback, retries
 * with backoff, and a circuit breaker per method.
 */
@Singleton
public final class AuthleteApiProvider implements Provider<AuthleteApi> {

  private static final Logger LOG = LoggerFactory.getLogger(AuthleteApiProvider.class);

  private final AuthleteApi api;

  @Inject
  public AuthleteApiProvider(AuthleteSettings settings, WSClient ws, Metrics metrics, Config config) {
    AuthleteSimpleConfiguration configuration =
        new AuthleteSimpleConfiguration()
            .setApiVersion("V3")
            .setBaseUrl(settings.baseUrl())
            .setServiceApiKey(Long.toString(settings.serviceId()))
            .setServiceAccessToken(settings.serviceAccessToken())
            .setDpopKey(settings.dpopKey().orElse(null));
    PlayAuthleteApiV3 client = new PlayAuthleteApiV3(configuration, ws);
    client
        .getSettings()
        .setReadTimeout((int) settings.readTimeout().toMillis())
        .setConnectionTimeout((int) settings.connectTimeout().toMillis());
    // Metered inside the resilience layer, so lattice_authlete_calls counts real HTTP calls (each
    // retry included, cache hits not); what the layer itself did is lattice_authlete_resilience.
    ResilientAuthleteApi.Wrapped resilient =
        ResilientAuthleteApi.wrap(
            MeteredAuthleteApi.wrap(client, metrics),
            new ResilienceConfig(config.getConfig("authlete.resilience")),
            metrics::authleteResilience);
    Gauge.builder("lattice.authlete.circuit.open", resilient.openBreakers()::getAsInt)
        .description("Authlete methods whose circuit breaker is open (calls fail fast)")
        .register(metrics.registry());
    this.api = resilient.api();
    LOG.info("Authlete client configured: {}", settings);
  }

  @Override
  public AuthleteApi get() {
    return api;
  }
}

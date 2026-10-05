package com.lattice.oidc.client;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.conf.AuthleteSimpleConfiguration;
import com.lattice.oidc.metrics.MeteredAuthleteApi;
import com.lattice.oidc.metrics.Metrics;
import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.libs.ws.WSClient;

/** Builds the process-wide Authlete client: on the Play WS transport, with every call timed. */
@Singleton
public final class AuthleteApiProvider implements Provider<AuthleteApi> {

  private static final Logger LOG = LoggerFactory.getLogger(AuthleteApiProvider.class);

  private final AuthleteApi api;

  @Inject
  public AuthleteApiProvider(AuthleteSettings settings, WSClient ws, Metrics metrics) {
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
    this.api = MeteredAuthleteApi.wrap(client, metrics);
    LOG.info("Authlete client configured: {}", settings);
  }

  @Override
  public AuthleteApi get() {
    return api;
  }
}

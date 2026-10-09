package com.lattice.oidc.handlers;

import com.authlete.common.api.AuthleteApi;
import com.lattice.oidc.common.JsonHelpers;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.common.ObbSupport;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.common.WebException;
import com.lattice.oidc.stores.ConsentStore;
import java.util.Map;
import java.util.Optional;
import jakarta.inject.Inject;
import jakarta.inject.Provider;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Open Banking Brasil: binds the refresh token from a successful (non-refresh) token response to
 * the consent named by its {@code consent:<id>} scope. Tokens for unknown consents are revoked and
 * the request is rejected.
 */
@Singleton
public final class ObbTokenHandler {

  private static final Logger LOG = LoggerFactory.getLogger(ObbTokenHandler.class);

  private final Provider<AuthleteApi> api;
  private final ConsentStore consents;
  private final LatticeConfig config;

  @Inject
  public ObbTokenHandler(Provider<AuthleteApi> api, ConsentStore consents, LatticeConfig config) {
    this.api = api;
    this.consents = consents;
    this.config = config;
  }

  /** Inspects a successful token response body; throws a WebException to reject it. */
  public void afterTokenIssued(String grantType, String responseJson, Map<String, String> headers) {
    if (!config.obbEnabled() || "refresh_token".equals(grantType) || responseJson == null) {
      return;
    }
    Map<String, Object> body = JsonHelpers.readMap(responseJson);
    Object refreshToken = body.get("refresh_token");
    Object scope = body.get("scope");
    if (!(refreshToken instanceof String refreshTokenValue) || !(scope instanceof String scopeValue)) {
      return;
    }
    String consentScope = ObbSupport.consentScope(scopeValue.split(" +"));
    if (consentScope == null) {
      return;
    }
    String consentId = consentScope.substring("consent:".length());
    Optional<com.lattice.oidc.models.Consent> consent = consents.find(consentId);
    if (consent.isEmpty()) {
      Object accessToken = body.get("access_token");
      if (accessToken instanceof String accessTokenValue) {
        try {
          api.get().tokenDelete(accessTokenValue);
        } catch (RuntimeException e) {
          LOG.warn("Could not delete access token issued for unknown consent: {}", e.getMessage());
        }
      }
      throw new WebException(
          Responses.badRequest(
              Responses.error(
                  "invalid_request", "There is no consent corresponding to the consent ID."),
              headers));
    }
    consents.save(consent.get().withRefreshToken(refreshTokenValue, ObbSupport.now()));
  }
}

package com.lattice.oidc.obb;

import com.authlete.common.api.AuthleteApi;
import com.lattice.oidc.config.LatticeConfig;
import com.lattice.oidc.http.Jsons;
import com.lattice.oidc.http.Responses;
import com.lattice.oidc.http.WebException;
import java.util.Map;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Open Banking Brasil: binds the refresh token from a successful (non-refresh) token response to
 * the consent named by its {@code consent:<id>} scope. Tokens for unknown consents are revoked and
 * the request is rejected.
 */
@Singleton
public final class ObbTokenTask {

  private static final Logger LOG = LoggerFactory.getLogger(ObbTokenTask.class);

  private final Provider<AuthleteApi> api;
  private final ConsentStore consents;
  private final LatticeConfig config;

  @Inject
  public ObbTokenTask(Provider<AuthleteApi> api, ConsentStore consents, LatticeConfig config) {
    this.api = api;
    this.consents = consents;
    this.config = config;
  }

  /** Inspects a successful token response body; throws a WebException to reject it. */
  public void afterTokenIssued(String grantType, String responseJson, Map<String, String> headers) {
    if (!config.obbEnabled() || "refresh_token".equals(grantType) || responseJson == null) {
      return;
    }
    Map<String, Object> body = Jsons.readMap(responseJson);
    Object refreshToken = body.get("refresh_token");
    Object scope = body.get("scope");
    if (!(refreshToken instanceof String rt) || !(scope instanceof String s)) {
      return;
    }
    String consentScope = ObbSupport.consentScope(s.split(" +"));
    if (consentScope == null) {
      return;
    }
    String consentId = consentScope.substring("consent:".length());
    Optional<com.lattice.oidc.obb.Consent> consent = consents.find(consentId);
    if (consent.isEmpty()) {
      Object accessToken = body.get("access_token");
      if (accessToken instanceof String at) {
        try {
          api.get().tokenDelete(at);
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
    consents.save(consent.get().withRefreshToken(rt, ObbSupport.now()));
  }
}

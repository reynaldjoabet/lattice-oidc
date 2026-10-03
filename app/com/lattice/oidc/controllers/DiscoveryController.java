package com.lattice.oidc.controllers;

import com.authlete.common.api.AuthleteApiException;
import com.authlete.common.dto.ServiceConfigurationRequest;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.common.Responses;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import javax.inject.Inject;
import play.mvc.Http;
import play.mvc.Result;

/**
 * Discovery endpoints.
 *
 * <ul>
 *   <li>{@code /.well-known/openid-configuration} and {@code /.well-known/oauth-authorization-server}:
 *       the OpenID Provider configuration / authorization server metadata.
 *   <li>{@code /api/jwks}: the JSON Web Key Set document of this server.
 *   <li>{@code /.well-known/apple-app-site-association}: lets a mobile app claim the authorization
 *       endpoint (app-to-app flows).
 * </ul>
 *
 * <p>An OpenID Provider that supports OpenID Connect Discovery 1.0 must provide an endpoint that
 * returns its configuration information in JSON format ("3. OpenID Provider Metadata"). The URI of
 * the endpoint is defined in "4.1. OpenID Provider Configuration Request": Issuer Identifier +
 * {@code /.well-known/openid-configuration}. The Issuer Identifier is a URL that identifies an
 * OpenID Provider, for example {@code https://example.com}; see {@code issuer} in OpenID Connect
 * Discovery 1.0 and {@code iss} in "2. ID Token" of OpenID Connect Core 1.0. It is configured in the
 * Authlete console; the default value is not appropriate for commercial use.
 *
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery 1.0</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8414.html">RFC 8414 OAuth 2.0 Authorization Server Metadata</a>
 */
public final class DiscoveryController extends BaseController {

  private final LatticeConfig config;

  @Inject
  public DiscoveryController(LatticeConfig config) {
    this.config = config;
  }

  /**
   * OpenID Provider configuration endpoint.
   *
   * <p>This implementation accepts {@code pretty} and {@code patch} as request parameters, but they
   * are not standardized ones. They are processed to expose capabilities of Authlete's
   * /service/configuration API. The value of {@code patch} is a JSON Patch (RFC 6902) that Authlete
   * applies to the configuration JSON before returning it.
   */
  public CompletionStage<Result> configuration(Http.Request request) {
    String pretty = request.queryString("pretty").orElse(null);
    String patch = request.queryString("patch").orElse(null);
    return async(
        () -> {
          String json =
              pretty == null && patch == null
                  ? api().getServiceConfiguration(true)
                  : api()
                      .getServiceConfiguration(
                          new ServiceConfigurationRequest()
                              .setPretty(pretty == null || pretty.isEmpty() || Boolean.parseBoolean(pretty))
                              .setPatch(patch));
          // Metadata is public and cacheable (unlike protocol responses).
          return ok(json).as(Responses.JSON).withHeader(CACHE_CONTROL, "public, max-age=300");
        });
  }

  /**
   * JWK Set endpoint.
   *
   * <p>An OpenID Provider is required to expose its JSON Web Key Set document (RFC 7517) so that
   * client applications can (1) verify signatures by the OP and (2) encrypt their requests to the OP.
   * The URI of the endpoint is the value of {@code jwks_uri} in the OpenID Provider Metadata.
   *
   * @see <a href="https://www.rfc-editor.org/rfc/rfc7517.html">RFC 7517, JSON Web Key (JWK)</a>
   */
  public CompletionStage<Result> jwks() {
    return async(
        () -> {
          try {
            // Call Authlete's /api/service/jwks/get API. It returns the JWK Set of the service. Of course,
            // private keys are not included.
            String jwks = api().getServiceJwks(true, false);
            if (jwks == null || jwks.isEmpty()) {
              return noContent();
            }
            return ok(jwks).as(Responses.JSON).withHeader(CACHE_CONTROL, "public, max-age=300");
          } catch (AuthleteApiException e) {
            // Authlete answers 302 when the service's JWK Set is hosted elsewhere (jwks_uri).
            if (e.getStatusCode() == 302) {
              List<String> location = header(e.getResponseHeaders(), "Location");
              if (location != null && !location.isEmpty()) {
                return Responses.location(location.get(0));
              }
            }
            throw e;
          }
        });
  }

  /**
   * Allows a mobile app to claim the authorization endpoint (universal links), for app-to-app
   * authorization flows. The JSON is taken from {@code lattice.apple-app-site-association}.
   *
   * @see <a href="https://openid.net/2019/10/21/guest-blog-implementing-app-to-app-authorisation-in-oauth2-openid-connect/">Implementing App-to-App Authorisation in OAuth2/OpenID Connect</a>
   */
  public Result appleAppSiteAssociation() {
    return config
        .appleAppSiteAssociation()
        .map(json -> ok(json).as("application/json"))
        .orElseGet(() -> notFound());
  }

  private static List<String> header(Map<String, List<String>> headers, String name) {
    if (headers == null) {
      return null;
    }
    for (Map.Entry<String, List<String>> e : headers.entrySet()) {
      if (e.getKey() != null && e.getKey().equalsIgnoreCase(name)) {
        return e.getValue();
      }
    }
    return null;
  }
}

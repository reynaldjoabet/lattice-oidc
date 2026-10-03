package com.lattice.oidc.controllers;

import com.authlete.common.dto.StandardIntrospectionRequest;
import com.authlete.common.dto.StandardIntrospectionResponse;
import com.authlete.common.types.JWEAlg;
import com.authlete.common.types.JWEEnc;
import com.authlete.common.types.JWSAlg;
import com.authlete.common.web.BasicCredentials;
import com.lattice.oidc.common.LatticeConfig.ResourceServer;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import javax.inject.Inject;
import play.mvc.Http;
import play.mvc.Result;

/**
 * An implementation of the introspection endpoint (RFC 7662): {@code POST /api/introspection}.
 *
 * <p>Callers authenticate as a configured resource server with HTTP Basic authentication. When the
 * resource server asks for a JWT response ({@code Accept: application/token-introspection+jwt}),
 * the response is signed and optionally encrypted as configured for that resource server (RFC 9701).
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7662.html">RFC 7662, OAuth 2.0 Token Introspection</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9701.html">RFC 9701, JWT Response for OAuth Token Introspection</a>
 */
public final class IntrospectionController extends BaseController {

  private static final String CHALLENGE = "Basic realm=\"introspection\"";

  private final LatticeConfig config;

  @Inject
  public IntrospectionController(LatticeConfig config) {
    this.config = config;
  }

  /**
   * The introspection endpoint.
   *
   * @see <a href="https://www.rfc-editor.org/rfc/rfc7662.html#section-2.1">RFC 7662, 2.1. Introspection Request</a>
   */
  public CompletionStage<Result> introspect(Http.Request request) {
    return async(
        () -> {
          Optional<ResourceServer> resourceServer = authenticate(Requests.basicCredentials(request));
          if (resourceServer.isEmpty()) {
            return Responses.unauthorized(
                Responses.error("invalid_client", "Resource server authentication failed."),
                CHALLENGE,
                null);
          }
          ResourceServer server = resourceServer.get();
          // Call Authlete's /api/auth/introspection/standard API.
          StandardIntrospectionResponse response =
              api()
                  .standardIntrospection(
                      new StandardIntrospectionRequest()
                          .setParameters(Requests.encode(Requests.form(request)))
                          .setHttpAcceptHeader(Requests.header(request, "Accept"))
                          .setRsUri(server.uri().map(URI::create).orElse(null))
                          .setIntrospectionSignAlg(
                              server.introspectionSignAlg().map(JWSAlg::parse).orElse(null))
                          .setIntrospectionEncryptionAlg(
                              server.introspectionEncryptionAlg().map(JWEAlg::parse).orElse(null))
                          .setIntrospectionEncryptionEnc(
                              server.introspectionEncryptionEnc().map(JWEEnc::parse).orElse(null))
                          .setSharedKeyForSign(server.sharedKeyForSign().orElse(null))
                          .setSharedKeyForEncryption(server.sharedKeyForEncryption().orElse(null))
                          .setPublicKeyForEncryption(server.publicKeyForEncryption().orElse(null)));
          String content = response.getResponseContent();
          return switch (response.getAction()) {
            // 200 OK
            case OK -> Responses.ok(content);
            // 200 OK; application/token-introspection+jwt
            case JWT -> Responses.of(200, content, Responses.TOKEN_INTROSPECTION, null);
            // 400 Bad Request
            case BAD_REQUEST -> Responses.badRequest(content);
            // 500 Internal Server Error
            case INTERNAL_SERVER_ERROR -> Responses.serverError(content);
            // This never happens.
            default -> throw unknownAction("/auth/introspection/standard", response.getAction());
          };
        });
  }

  /** Constant-time secret comparison against the configured resource servers. */
  private Optional<ResourceServer> authenticate(BasicCredentials credentials) {
    if (credentials == null || credentials.getUserId() == null || credentials.getPassword() == null) {
      return Optional.empty();
    }
    byte[] presented = credentials.getPassword().getBytes(StandardCharsets.UTF_8);
    return config.resourceServers().stream()
        .filter(resourceServer -> resourceServer.id().equals(credentials.getUserId()))
        .filter(resourceServer -> MessageDigest.isEqual(resourceServer.secret().getBytes(StandardCharsets.UTF_8), presented))
        .findFirst();
  }
}

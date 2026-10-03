package com.lattice.oidc.endpoints;

import com.authlete.common.dto.Client;
import com.authlete.common.dto.ClientRegistrationRequest;
import com.authlete.common.dto.ClientRegistrationResponse;
import com.authlete.common.web.BearerToken;
import com.lattice.oidc.config.LatticeConfig;
import com.lattice.oidc.http.AuthleteController;
import com.lattice.oidc.http.Requests;
import com.lattice.oidc.http.Responses;
import com.lattice.oidc.http.WebException;
import com.lattice.oidc.obb.ObbCertValidator;
import com.lattice.oidc.obb.ObbDcrProcessor;
import java.security.GeneralSecurityException;
import java.util.concurrent.CompletionStage;
import javax.inject.Inject;
import play.mvc.BodyParser;
import play.mvc.Http;
import play.mvc.Result;

/**
 * An implementation of the dynamic client registration and dynamic client registration management
 * endpoints.
 *
 * <p>Registration requests are taken via {@code POST} to {@code /api/register}, and the resulting
 * registered client is returned as JSON. Client management requests are taken via {@code GET},
 * {@code PUT} and {@code DELETE} to {@code /api/register/:client_id}; the client ID is parsed from
 * the URL and passed to the Authlete API together with the registration access token.
 *
 * <p>Open Banking Brasil registrations additionally require a valid directory software statement
 * and an OBB client certificate (see {@link ObbDcrProcessor}).
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7591.html">RFC 7591</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7592.html">RFC 7592</a>
 * @see <a href="https://openid.net/specs/openid-connect-registration-1_0.html">OpenID Connect Dynamic Client Registration</a>
 */
public final class ClientRegistrationController extends AuthleteController {

  private final LatticeConfig config;
  private final ObbDcrProcessor obbDcr;
  private final ObbCertValidator obbCerts;

  @Inject
  public ClientRegistrationController(
      LatticeConfig config, ObbDcrProcessor obbDcr, ObbCertValidator obbCerts) {
    this.config = config;
    this.obbDcr = obbDcr;
    this.obbCerts = obbCerts;
  }

  /**
   * Dynamic client registration endpoint. The optional bearer token is an initial access token.
   */
  @BodyParser.Of(BodyParser.TolerantText.class)
  public CompletionStage<Result> register(Http.Request request) {
    String body = request.body().asText();
    return async(
        () -> {
          String json = preprocess(request, body);
          return respond(
              api()
                  .dynamicClientRegister(
                      new ClientRegistrationRequest().setJson(json).setToken(bearer(request))));
        });
  }

  /**
   * Dynamic client registration management endpoint, "read" functionality.
   */
  public CompletionStage<Result> read(Http.Request request, String clientId) {
    return async(
        () -> {
          requireObbCertIfObbClient(request, clientId);
          return respond(
              api()
                  .dynamicClientGet(
                      new ClientRegistrationRequest().setClientId(clientId).setToken(bearer(request))));
        });
  }

  /**
   * Dynamic client registration management endpoint, "update" functionality.
   */
  @BodyParser.Of(BodyParser.TolerantText.class)
  public CompletionStage<Result> update(Http.Request request, String clientId) {
    String body = request.body().asText();
    return async(
        () -> {
          String json = preprocess(request, body);
          return respond(
              api()
                  .dynamicClientUpdate(
                      new ClientRegistrationRequest()
                          .setClientId(clientId)
                          .setJson(json)
                          .setToken(bearer(request))));
        });
  }

  /**
   * Dynamic client registration management endpoint, "delete" functionality.
   */
  public CompletionStage<Result> delete(Http.Request request, String clientId) {
    return async(
        () -> {
          requireObbCertIfObbClient(request, clientId);
          return respond(
              api()
                  .dynamicClientDelete(
                      new ClientRegistrationRequest().setClientId(clientId).setToken(bearer(request))));
        });
  }

  private static String bearer(Http.Request request) {
    return BearerToken.parse(Requests.authorization(request));
  }

  private String preprocess(Http.Request request, String body) {
    if (!config.obbEnabled()) {
      return body;
    }
    String[] chain = requests.clientCertificateChain(request);
    boolean obbCert = obbCerts.configured() && obbCerts.isValid(chain);
    if (!ObbDcrProcessor.isObbRequest(body) && !obbCert) {
      return body;
    }
    validateCertificate(chain);
    return obbDcr.process(body);
  }

  private void requireObbCertIfObbClient(Http.Request request, String clientId) {
    if (!config.obbEnabled()) {
      return;
    }
    Client client;
    try {
      client = api().getClient(clientId);
    } catch (RuntimeException e) {
      return; // Authlete's registration API will report unknown clients itself.
    }
    if (client != null
        && client.getCustomMetadata() != null
        && client.getCustomMetadata().contains("\"software_roles\"")) {
      validateCertificate(requests.clientCertificateChain(request));
    }
  }

  private void validateCertificate(String[] chain) {
    try {
      obbCerts.validate(chain);
    } catch (GeneralSecurityException e) {
      throw new WebException(
          Responses.unauthorized(
              Responses.error("invalid_client", "Client certificate validation failed: " + e.getMessage()),
              null,
              null));
    }
  }

  private Result respond(ClientRegistrationResponse r) {
    String content = r.getResponseContent();
    return switch (r.getAction()) {
      // 201 Created
      case CREATED -> Responses.created(content, null);
      // 200 OK
      case OK, UPDATED -> Responses.ok(content);
      // 204 No Content
      case DELETED -> Responses.noContent(null);
      // 400 Bad Request
      case BAD_REQUEST -> Responses.badRequest(content);
      // 401 Unauthorized
      case UNAUTHORIZED -> Responses.unauthorized(content, null, null);
      // 500 Internal Server Error
      case INTERNAL_SERVER_ERROR -> Responses.serverError(content);
      // This never happens.
      default -> throw unknownAction("/client/registration", r.getAction());
    };
  }
}

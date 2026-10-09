package com.lattice.oidc.controllers;

import com.authlete.common.dto.BackchannelAuthenticationRequest;
import com.authlete.common.dto.BackchannelAuthenticationResponse;
import com.authlete.common.web.BasicCredentials;
import com.lattice.oidc.common.JsonHelpers;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.handlers.AuthenticationDevice;
import com.lattice.oidc.handlers.CibaHandler;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import jakarta.inject.Inject;
import play.mvc.BodyParser;
import play.mvc.Http;
import play.mvc.Result;

/**
 * An implementation of the backchannel authentication endpoint of CIBA (OpenID Connect
 * Client-Initiated Backchannel Authentication), plus the endpoint called back from the
 * authentication device when it is used in asynchronous mode.
 *
 * <ul>
 *   <li>{@code POST /api/backchannel/authentication}
 *   <li>{@code POST /api/backchannel/authentication/callback}
 * </ul>
 *
 * @see <a href="https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html">OpenID Connect Client-Initiated Backchannel Authentication Flow - Core 1.0</a>
 */
public final class CibaController extends BaseController {

  private static final String CHALLENGE = "Basic realm=\"backchannel/authentication\"";

  private final CibaHandler ciba;

  @Inject
  public CibaController(CibaHandler ciba) {
    this.ciba = ciba;
  }

  /**
   * The backchannel authentication endpoint.
   */
  public CompletionStage<Result> authenticate(Http.Request request) {
    return async(
        () -> {
          BasicCredentials basic = Requests.basicCredentials(request);
          String[] chain = requests.clientCertificateChain(request);
          // Call Authlete's /api/backchannel/authentication API.
          BackchannelAuthenticationResponse backchannelResponse =
              api()
                  .backchannelAuthentication(
                      new BackchannelAuthenticationRequest()
                          .setParameters(Requests.encode(Requests.form(request)))
                          .setClientId(basic == null ? null : basic.getUserId())
                          .setClientSecret(basic == null ? null : basic.getPassword())
                          .setClientCertificate(chain == null ? null : chain[0])
                          .setClientCertificatePath(
                              chain == null || chain.length < 2 ? null : Arrays.copyOfRange(chain, 1, chain.length))
                          .setOauthClientAttestation(Requests.header(request, "OAuth-Client-Attestation"))
                          .setOauthClientAttestationPop(Requests.header(request, "OAuth-Client-Attestation-PoP")));
          Map<String, String> headers = new LinkedHashMap<>();
          if (backchannelResponse.getAttestationChallenge() != null) {
            headers.put("OAuth-Client-Attestation-Challenge", backchannelResponse.getAttestationChallenge());
          }
          String content = backchannelResponse.getResponseContent();
          return switch (backchannelResponse.getAction()) {
            // Process user identification.
            case USER_IDENTIFICATION -> Responses.ok(ciba.identifyAndIssue(backchannelResponse), headers);
            // 400 Bad Request
            case BAD_REQUEST -> Responses.badRequest(content, headers);
            // 401 Unauthorized
            case UNAUTHORIZED -> Responses.unauthorized(content, CHALLENGE, headers);
            // 500 Internal Server Error
            case INTERNAL_SERVER_ERROR -> Responses.serverError(content, headers);
            // This never happens.
            default -> throw unknownAction("/backchannel/authentication", backchannelResponse.getAction());
          };
        });
  }

  /**
   * The callback endpoint called back from the authentication device when it is used in asynchronous
   * mode. The result of the end-user authentication and authorization is expected to be contained in
   * the request. It is assumed that this server has made a request to the authentication device in
   * {@link CibaHandler#start} before this endpoint is called back.
   */
  @BodyParser.Of(BodyParser.TolerantText.class)
  public CompletionStage<Result> callback(Http.Request request) {
    String body = request.body().asText();
    return async(
        () -> {
          Map<String, Object> json;
          try {
            json = JsonHelpers.readMap(body);
          } catch (RuntimeException e) {
            return Responses.badRequest(Responses.error("invalid_request", "The body must be JSON."));
          }
          Object requestId = json.get("request_id");
          if (!(requestId instanceof String id) || id.isEmpty() || json.get("result") == null) {
            return Responses.badRequest(Responses.error("invalid_request", "request_id and result are required."));
          }
          boolean known = ciba.callback(id, AuthenticationDevice.outcome(json.get("result")));
          return known
              ? Responses.noContent(null)
              : Responses.badRequest(Responses.error("invalid_request", "Unknown request_id."));
        });
  }
}

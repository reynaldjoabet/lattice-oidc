package com.lattice.oidc.controllers;

import com.authlete.common.dto.RevocationRequest;
import com.authlete.common.dto.RevocationResponse;
import com.authlete.common.web.BasicCredentials;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import play.mvc.Http;
import play.mvc.Result;

/**
 * An implementation of the revocation endpoint (RFC 7009): {@code POST /api/revocation}.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7009.html">RFC 7009: OAuth 2.0 Token Revocation</a>
 */
public final class RevocationController extends BaseController {

  private static final String CHALLENGE = "Basic realm=\"revocation\"";

  /**
   * The revocation endpoint for the {@code POST} method. Client authentication works as on the
   * token endpoint.
   *
   * @see <a href="https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1">RFC 7009, 2.1. Revocation Request</a>
   */
  public CompletionStage<Result> revoke(Http.Request request) {
    return async(
        () -> {
          BasicCredentials basic = Requests.basicCredentials(request);
          String[] chain = requests.clientCertificateChain(request);
          // Call Authlete's /api/auth/revocation API.
          RevocationResponse response =
              api()
                  .revocation(
                      new RevocationRequest()
                          .setParameters(Requests.encode(Requests.form(request)))
                          .setClientId(basic == null ? null : basic.getUserId())
                          .setClientSecret(basic == null ? null : basic.getPassword())
                          .setClientCertificate(chain == null ? null : chain[0])
                          .setClientCertificatePath(rest(chain))
                          .setOauthClientAttestation(Requests.header(request, "OAuth-Client-Attestation"))
                          .setOauthClientAttestationPop(
                              Requests.header(request, "OAuth-Client-Attestation-PoP")));
          Map<String, String> headers = new LinkedHashMap<>();
          if (response.getAttestationChallenge() != null) {
            headers.put("OAuth-Client-Attestation-Challenge", response.getAttestationChallenge());
          }
          String content = response.getResponseContent();
          return switch (response.getAction()) {
            // Content is empty for plain revocation, or JavaScript for JSONP callbacks.
            // 200 OK
            case OK -> Responses.of(200, content, Responses.JAVASCRIPT, headers);
            // 401 Unauthorized
            case INVALID_CLIENT -> Responses.unauthorized(content, CHALLENGE, headers);
            // 400 Bad Request
            case BAD_REQUEST -> Responses.badRequest(content, headers);
            // 500 Internal Server Error
            case INTERNAL_SERVER_ERROR -> Responses.serverError(content, headers);
            // This never happens.
            default -> throw unknownAction("/auth/revocation", response.getAction());
          };
        });
  }

  /**
   * The second and subsequent elements in the client certificate path.
   */
  static String[] rest(String[] chain) {
    return chain == null || chain.length < 2 ? null : Arrays.copyOfRange(chain, 1, chain.length);
  }
}

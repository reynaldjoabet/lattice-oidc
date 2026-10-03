package com.lattice.oidc.controllers;

import com.authlete.common.dto.PushedAuthReqRequest;
import com.authlete.common.dto.PushedAuthReqResponse;
import com.authlete.common.web.BasicCredentials;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import play.mvc.Http;
import play.mvc.Result;

/**
 * An implementation of the pushed authorization request endpoint (RFC 9126): {@code POST /api/par}.
 *
 * <p>The endpoint uses the {@code POST} method and the same client authentication as is available
 * on the token endpoint. The {@code request_uri} it returns is then used at the authorization
 * endpoint.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9126.html">RFC 9126 OAuth 2.0 Pushed Authorization Requests</a>
 */
public final class PushedAuthorizationController extends BaseController {

  public CompletionStage<Result> push(Http.Request request) {
    return async(
        () -> {
          BasicCredentials basic = Requests.basicCredentials(request);
          String[] chain = requests.clientCertificateChain(request);
          // Call Authlete's /api/pushed_auth_req API.
          PushedAuthReqResponse response =
              api()
                  .pushAuthorizationRequest(
                      new PushedAuthReqRequest()
                          .setParameters(Requests.encode(Requests.form(request)))
                          .setClientId(basic == null ? null : basic.getUserId())
                          .setClientSecret(basic == null ? null : basic.getPassword())
                          .setClientCertificate(chain == null ? null : chain[0])
                          .setClientCertificatePath(RevocationController.rest(chain))
                          .setDpop(Requests.header(request, "DPoP"))
                          .setHtm("POST")
                          .setHtu(requests.htu(request))
                          .setOauthClientAttestation(Requests.header(request, "OAuth-Client-Attestation"))
                          .setOauthClientAttestationPop(
                              Requests.header(request, "OAuth-Client-Attestation-PoP")));
          Map<String, String> headers = new LinkedHashMap<>();
          if (response.getDpopNonce() != null) {
            headers.put("DPoP-Nonce", response.getDpopNonce());
          }
          if (response.getAttestationChallenge() != null) {
            headers.put("OAuth-Client-Attestation-Challenge", response.getAttestationChallenge());
          }
          String content = response.getResponseContent();
          return switch (response.getAction()) {
            // 201 Created
            case CREATED -> Responses.created(content, headers);
            // 400 Bad Request
            case BAD_REQUEST -> Responses.badRequest(content, headers);
            // 401 Unauthorized
            case UNAUTHORIZED -> Responses.unauthorized(content, null, headers);
            // 403 Forbidden
            case FORBIDDEN -> Responses.forbidden(content, headers);
            // 413 Payload Too Large
            case PAYLOAD_TOO_LARGE -> Responses.tooLarge(content, headers);
            // 500 Internal Server Error
            case INTERNAL_SERVER_ERROR -> Responses.serverError(content, headers);
            // This never happens.
            default -> throw unknownAction("/pushed_auth_req", response.getAction());
          };
        });
  }
}

package com.lattice.oidc.endpoints;

import com.authlete.common.dto.GMRequest;
import com.authlete.common.dto.GMResponse;
import com.authlete.common.types.GMAction;
import com.lattice.oidc.http.AuthleteController;
import com.lattice.oidc.http.Requests;
import com.lattice.oidc.http.Responses;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import play.mvc.Http;
import play.mvc.Result;

/**
 * An implementation of the Grant Management endpoint: {@code GET|DELETE /api/gm/:grantId}.
 *
 * @see <a href="https://openid.net/specs/fapi-grant-management.html">Grant Management for OAuth 2.0</a>
 */
public final class GrantManagementController extends AuthleteController {

  /**
   * The entry point for grant management 'query' requests.
   */
  public CompletionStage<Result> query(Http.Request request, String grantId) {
    return async(() -> handle(request, grantId, GMAction.QUERY));
  }

  /**
   * The entry point for grant management 'revoke' requests.
   */
  public CompletionStage<Result> revoke(Http.Request request, String grantId) {
    return async(() -> handle(request, grantId, GMAction.REVOKE));
  }

  private Result handle(Http.Request request, String grantId, GMAction action) {
    // Call Authlete's /api/gm API.
    GMResponse response =
        api()
            .gm(
                new GMRequest()
                    .setGmAction(action)
                    .setGrantId(grantId)
                    .setAccessToken(Requests.accessToken(request, null))
                    .setClientCertificate(requests.clientCertificate(request))
                    .setDpop(Requests.header(request, "DPoP"))
                    .setHtm(request.method())
                    .setHtu(requests.htu(request)));
    Map<String, String> headers = new LinkedHashMap<>();
    if (response.getDpopNonce() != null) {
      headers.put("DPoP-Nonce", response.getDpopNonce());
    }
    String content = response.getResponseContent();
    return switch (response.getAction()) {
      // 200 OK
      case OK -> Responses.ok(content, headers);
      // 204 No Content
      case NO_CONTENT -> Responses.noContent(headers);
      // 401 Unauthorized
      case UNAUTHORIZED -> Responses.unauthorized(content, null, headers);
      // 403 Forbidden
      case FORBIDDEN -> Responses.forbidden(content, headers);
      // 404 Not Found
      case NOT_FOUND -> Responses.json(404, content, headers);
      // 500 Internal Server Error
      case CALLER_ERROR, AUTHLETE_ERROR -> Responses.serverError(content, headers);
      // This should not happen.
      default -> throw unknownAction("/gm", response.getAction());
    };
  }
}

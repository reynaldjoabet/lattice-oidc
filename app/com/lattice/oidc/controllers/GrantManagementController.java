package com.lattice.oidc.controllers;

import com.authlete.common.dto.GMRequest;
import com.authlete.common.dto.GMResponse;
import com.authlete.common.types.GMAction;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.mvc.Http;
import play.mvc.Result;

/**
 * An implementation of the Grant Management endpoint: {@code GET|DELETE /api/gm/:grantId}.
 *
 * @see <a href="https://openid.net/specs/fapi-grant-management.html">Grant Management for OAuth 2.0</a>
 */
public final class GrantManagementController extends BaseController {

  private static final Logger LOG = LoggerFactory.getLogger(GrantManagementController.class);

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
      // 200 OK, with the grant as JSON.
      case OK -> Responses.ok(content, headers);
      // 204 No Content: the grant and its tokens are revoked.
      case NO_CONTENT -> Responses.noContent(headers);
      // For errors, Authlete's response content is a WWW-Authenticate value, such as
      // 'Bearer error="invalid_token", ...' or a DPoP "use_dpop_nonce" challenge: it goes in that
      // header, with no body (RFC 6750), as on the UserInfo endpoint.
      case UNAUTHORIZED -> Responses.bearerError(401, content, headers);
      case FORBIDDEN -> Responses.bearerError(403, content, headers);
      case NOT_FOUND -> Responses.bearerError(404, content, headers);
      // A mistake in Lattice's call, or a failure at Authlete: logged, and a generic error for the
      // client rather than Authlete's message.
      case CALLER_ERROR -> {
        LOG.error("Authlete's /gm refused Lattice's request: {}", response.getResultMessage());
        yield Responses.serverError(Responses.error("server_error", "The grant could not be processed."), headers);
      }
      case AUTHLETE_ERROR -> {
        LOG.warn("Authlete's /gm failed: {}", response.getResultMessage());
        yield Responses.serverError(Responses.error("server_error", "The grant could not be processed."), headers);
      }
      // This should not happen.
      default -> throw unknownAction("/gm", response.getAction());
    };
  }
}

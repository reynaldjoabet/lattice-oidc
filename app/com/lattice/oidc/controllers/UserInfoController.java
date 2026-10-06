package com.lattice.oidc.controllers;

import com.authlete.common.dto.UserInfoIssueRequest;
import com.authlete.common.dto.UserInfoIssueResponse;
import com.authlete.common.dto.UserInfoRequest;
import com.authlete.common.dto.UserInfoResponse;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.handlers.ClaimsCollector;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.UserStore;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import jakarta.inject.Inject;
import play.mvc.BodyParser;
import play.mvc.Http;
import play.mvc.Result;

/**
 * An implementation of the userinfo endpoint (OpenID Connect Core 1.0, 5.3. UserInfo Endpoint):
 * {@code GET|POST /api/userinfo}.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">OpenID Connect Core 1.0, 5.3. UserInfo Endpoint</a>
 */
public final class UserInfoController extends BaseController {

  private static final String MISSING_TOKEN =
      "Bearer error=\"invalid_token\",error_description=\"An access token must be sent as a Bearer"
          + " or DPoP token.\"";

  private final UserStore users;

  @Inject
  public UserInfoController(UserStore users) {
    this.users = users;
  }

  /**
   * The userinfo endpoint for the {@code GET} method. The access token is taken from the {@code
   * Authorization} header ({@code Bearer} or {@code DPoP} scheme).
   *
   * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoRequest">OpenID Connect Core 1.0, 5.3.1. UserInfo Request</a>
   */
  public CompletionStage<Result> get(Http.Request request) {
    return async(() -> process(request, Requests.accessToken(request, null), false));
  }

  /**
   * The userinfo endpoint for the {@code POST} method. The access token may also be sent as the
   * {@code access_token} form parameter (RFC 6750, 2.2. Form-Encoded Body Parameter).
   *
   * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoRequest">OpenID Connect Core 1.0, 5.3.1. UserInfo Request</a>
   */
  @BodyParser.Of(BodyParser.TolerantText.class)
  public CompletionStage<Result> post(Http.Request request) {
    String body = request.body().asText();
    String formToken =
        request.contentType().orElse("").equalsIgnoreCase("application/x-www-form-urlencoded")
            ? Requests.first(Requests.decode(body), "access_token")
            : null;
    return async(
        () ->
            process(
                request,
                Requests.accessToken(request, formToken),
                body != null && !body.isEmpty()));
  }

  /**
   * Handle the userinfo request.
   */
  private Result process(Http.Request request, String accessToken, boolean bodyContained) {
    // If an access token is not available, return "400 Bad Request".
    if (accessToken == null) {
      return Responses.bearerError(400, MISSING_TOKEN, null);
    }
    // Call Authlete's /api/auth/userinfo API. The request headers and target URI are passed for
    // HTTP Message Signatures (RFC 9421), and the DPoP proof / client certificate for sender-constrained
    // access tokens.
    UserInfoResponse response =
        api()
            .userinfo(
                new UserInfoRequest()
                    .setToken(accessToken)
                    .setClientCertificate(requests.clientCertificate(request))
                    .setDpop(Requests.header(request, "DPoP"))
                    .setHtm(request.method())
                    .setHtu(requests.htu(request))
                    .setTargetUri(URI.create(requests.requestUrl(request)))
                    .setHeaders(Requests.headersAsPairs(request))
                    .setRequestBodyContained(bodyContained));
    // Additional HTTP headers: DPoP-Nonce.
    Map<String, String> headers = new LinkedHashMap<>();
    if (response.getDpopNonce() != null) {
      headers.put("DPoP-Nonce", response.getDpopNonce());
    }
    String content = response.getResponseContent();
    // 'action' in the response denotes the next action which
    // this service implementation should take. Dispatch according to the action.
    return switch (response.getAction()) {
      // Return the user information.
      case OK -> issue(response, headers);
      // 400 Bad Request / 401 Unauthorized / 403 Forbidden / 500 Internal Server Error. In these cases
      // the content is the value of the WWW-Authenticate header (RFC 6750, 3. The WWW-Authenticate
      // Response Header Field).
      case BAD_REQUEST -> Responses.bearerError(400, content, headers);
      case UNAUTHORIZED -> Responses.bearerError(401, content, headers);
      case FORBIDDEN -> Responses.bearerError(403, content, headers);
      case INTERNAL_SERVER_ERROR -> Responses.bearerError(500, content, headers);
      // This never happens.
      default -> throw unknownAction("/auth/userinfo", response.getAction());
    };
  }

  /**
   * Generates a JSON or a JWT containing user information by calling Authlete's
   * /api/auth/userinfo/issue API.
   */
  private Result issue(UserInfoResponse info, Map<String, String> headers) {
    // Collect claim values of the user identified by the subject associated with the access token.
    Optional<User> user = users.bySubject(info.getSubject());
    Map<String, Object> claims = null;
    Map<String, Object> claimsForTx = null;
    List<Map<String, Object>> verifiedForTx = null;
    if (user.isPresent()) {
      ClaimsCollector collector = new ClaimsCollector(user.get());
      claims = collector.withVerifiedClaims(collector.collect(info.getClaims(), null), info.getUserInfoClaims());
      // Collect claim data that are referenced when Authlete computes values of transformed claims.
      claimsForTx = collector.collect(info.getRequestedClaimsForTx(), null);
      // Values of verified claims that are used to compute values of transformed claims under
      // "verified_claims/claims".
      verifiedForTx =
          collector.verifiedClaimsForTx(info.getUserInfoClaims(), info.getRequestedVerifiedClaimsForTx());
    }
    UserInfoIssueRequest request = new UserInfoIssueRequest().setToken(info.getToken());
    if (claims != null && !claims.isEmpty()) {
      request.setClaims(claims);
    }
    if (claimsForTx != null && !claimsForTx.isEmpty()) {
      request.setClaimsForTx(claimsForTx);
    }
    if (verifiedForTx != null && !verifiedForTx.isEmpty()) {
      request.setVerifiedClaimsForTx(verifiedForTx);
    }
    UserInfoIssueResponse response = api().userinfoIssue(request);
    String content = response.getResponseContent();
    return switch (response.getAction()) {
      // 200 OK; application/json
      case JSON -> Responses.ok(content, headers);
      // 200 OK; application/jwt (signed and/or encrypted userinfo)
      case JWT -> Responses.of(200, content, Responses.JWT, headers);
      // 400 Bad Request / 401 Unauthorized / 403 Forbidden / 500 Internal Server Error, with the
      // content as the WWW-Authenticate challenge.
      case BAD_REQUEST -> Responses.bearerError(400, content, headers);
      case UNAUTHORIZED -> Responses.bearerError(401, content, headers);
      case FORBIDDEN -> Responses.bearerError(403, content, headers);
      case INTERNAL_SERVER_ERROR -> Responses.bearerError(500, content, headers);
      // This never happens.
      default -> throw unknownAction("/auth/userinfo/issue", response.getAction());
    };
  }
}

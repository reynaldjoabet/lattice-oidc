package com.lattice.oidc.controllers;

import com.authlete.common.dto.Property;
import com.authlete.common.dto.TokenFailRequest;
import com.authlete.common.dto.TokenFailResponse;
import com.authlete.common.dto.TokenIssueRequest;
import com.authlete.common.dto.TokenIssueResponse;
import com.authlete.common.dto.TokenRequest;
import com.authlete.common.dto.TokenResponse;
import com.authlete.common.web.BasicCredentials;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.handlers.NativeSsoHandler;
import com.lattice.oidc.handlers.ObbTokenHandler;
import com.lattice.oidc.handlers.TokenGrantHandler;
import com.lattice.oidc.security.LoginService;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import javax.inject.Inject;
import play.mvc.Http;
import play.mvc.Result;

/**
 * An implementation of the OAuth 2.0 token endpoint with OpenID Connect support:
 * {@code POST /api/token}.
 *
 * <p>Besides the grant types Authlete completes by itself (authorization code, refresh token,
 * client credentials, CIBA, device code, pre-authorized code), this endpoint handles the grants
 * Authlete delegates to the authorization server: resource owner password credentials, token
 * exchange (RFC 8693), JWT authorization grants (RFC 7523) and Native SSO.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2">RFC 6749, 3.2. Token Endpoint</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint">OpenID Connect Core 1.0, 3.1.3. Token Endpoint</a>
 */
public final class TokenController extends BaseController {

  private static final String CHALLENGE = "Basic realm=\"token\"";

  private final LoginService login;
  private final TokenGrantHandler grants;
  private final NativeSsoHandler nativeSso;
  private final ObbTokenHandler obb;

  @Inject
  public TokenController(
      LoginService login, TokenGrantHandler grants, NativeSsoHandler nativeSso, ObbTokenHandler obb) {
    this.login = login;
    this.grants = grants;
    this.nativeSso = nativeSso;
    this.obb = obb;
  }

  /**
   * The token endpoint for the {@code POST} method.
   *
   * <p>RFC 6749, 3.2. Token Endpoint says: "The client MUST use the HTTP "POST" method when making
   * access token requests."
   *
   * <p>RFC 6749, 2.3. Client Authentication mentions (1) HTTP Basic Authentication and (2) {@code
   * client_id} &amp; {@code client_secret} parameters in the request body as the means of client
   * authentication. This implementation supports both means, plus TLS client certificates (RFC
   * 8705), private_key_jwt and OAuth 2.0 Attestation-Based Client Authentication, which Authlete
   * validates.
   *
   * @see <a href="https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2">RFC 6749, 3.2. Token Endpoint</a>
   */
  public CompletionStage<Result> token(Http.Request request) {
    return async(() -> process(request));
  }

  private Result process(Http.Request request) {
    Map<String, String[]> params = Requests.form(request);
    // The credential of the client application extracted from the Authorization header, if any:
    // the client ID and the client secret.
    BasicCredentials basic = Requests.basicCredentials(request);
    // The client certificate (first element) and the second and subsequent elements in the client
    // certificate path, for mutual TLS client authentication and certificate-bound tokens.
    String[] chain = requests.clientCertificateChain(request);

    // Call Authlete's /api/auth/token API.
    TokenResponse response =
        api()
            .token(
                new TokenRequest()
                    .setParameters(Requests.encode(params))
                    .setClientId(basic == null ? null : basic.getUserId())
                    .setClientSecret(basic == null ? null : basic.getPassword())
                    .setClientCertificate(chain == null ? null : chain[0])
                    .setClientCertificatePath(
                        chain == null || chain.length < 2
                            ? null
                            : Arrays.copyOfRange(chain, 1, chain.length))
                    .setDpop(Requests.header(request, "DPoP"))
                    .setHtm("POST")
                    .setHtu(requests.htu(request))
                    .setOauthClientAttestation(Requests.header(request, "OAuth-Client-Attestation"))
                    .setOauthClientAttestationPop(
                        Requests.header(request, "OAuth-Client-Attestation-PoP")));

    // Additional HTTP headers: DPoP-Nonce (RFC 9449) and OAuth-Client-Attestation-Challenge.
    Map<String, String> headers = new LinkedHashMap<>();
    if (response.getDpopNonce() != null) {
      headers.put("DPoP-Nonce", response.getDpopNonce());
    }
    if (response.getAttestationChallenge() != null) {
      headers.put("OAuth-Client-Attestation-Challenge", response.getAttestationChallenge());
    }
    String content = response.getResponseContent();

    // 'action' in the response denotes the next action which
    // this service implementation should take. Dispatch according to the action.
    return switch (response.getAction()) {
      // 200 OK. For Open Banking Brasil, the refresh token is bound to the consent of its
      // "consent:" scope first.
      case OK -> {
        obb.afterTokenIssued(Requests.first(params, "grant_type"), content, headers);
        yield Responses.ok(content, headers);
      }
      // The flow of the token request is the refresh token flow and an ID token can be reissued.
      // Returning the content as is makes the token endpoint behave in the same way as before, and
      // no ID token is reissued.
      case ID_TOKEN_REISSUABLE -> Responses.ok(content, headers);
      // 401 Unauthorized
      case INVALID_CLIENT -> Responses.unauthorized(content, CHALLENGE, headers);
      // 400 Bad Request
      case BAD_REQUEST -> Responses.badRequest(content, headers);
      // 500 Internal Server Error
      case INTERNAL_SERVER_ERROR -> Responses.serverError(content, headers);
      // Process the token request whose flow is "Resource Owner Password Credentials".
      case PASSWORD -> password(request, response, headers);
      // Process the token exchange request (RFC 8693).
      case TOKEN_EXCHANGE -> grants.tokenExchange(response, headers);
      // Process the token request which uses the grant type
      // urn:ietf:params:oauth:grant-type:jwt-bearer (RFC 7523).
      case JWT_BEARER -> grants.jwtBearer(response, headers);
      // The token request complies with the "OpenID Connect Native SSO for Mobile Apps 1.0"
      // specification (a.k.a. "Native SSO").
      case NATIVE_SSO -> nativeSso.process(response, headers);
      // This never happens.
      default -> throw unknownAction("/auth/token", response.getAction());
    };
  }

  /**
   * Resource owner password credentials grant (RFC 6749, 4.3). Authlete only returns the PASSWORD
   * action when the grant type is enabled for the service and the client.
   */
  private Result password(
      Http.Request request, TokenResponse response, Map<String, String> headers) {
    // Validate the credentials of the resource owner (with brute-force protection).
    LoginService.Result auth = login.authenticate(response.getUsername(), response.getPassword(), request.remoteAddress());
    auditLogin(request, response.getUsername(), auth);
    if (auth.outcome() != LoginService.Outcome.SUCCESS) {
      // The credentials are invalid. An access token is not issued; Authlete's /api/auth/token/fail
      // API generates the error response.
      TokenFailResponse fail =
          api()
              .tokenFail(
                  new TokenFailRequest()
                      .setTicket(response.getTicket())
                      .setReason(TokenFailRequest.Reason.INVALID_RESOURCE_OWNER_CREDENTIALS));
      return switch (fail.getAction()) {
        case BAD_REQUEST -> Responses.badRequest(fail.getResponseContent(), headers);
        default -> Responses.serverError(fail.getResponseContent(), headers);
      };
    }
    // Issue an access token and optionally an ID token by calling Authlete's /api/auth/token/issue
    // API with the ticket and the authenticated subject.
    TokenIssueResponse issue =
        api()
            .tokenIssue(
                new TokenIssueRequest()
                    .setTicket(response.getTicket())
                    .setSubject(auth.user().get().getSubject())
                    .setProperties((Property[]) null));
    return switch (issue.getAction()) {
      case OK -> Responses.ok(issue.getResponseContent(), headers);
      default -> Responses.serverError(issue.getResponseContent(), headers);
    };
  }
}

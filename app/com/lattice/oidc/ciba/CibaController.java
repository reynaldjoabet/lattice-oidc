package com.lattice.oidc.ciba;

import com.authlete.common.dto.BackchannelAuthenticationFailRequest;
import com.authlete.common.dto.BackchannelAuthenticationFailRequest.Reason;
import com.authlete.common.dto.BackchannelAuthenticationFailResponse;
import com.authlete.common.dto.BackchannelAuthenticationIssueRequest;
import com.authlete.common.dto.BackchannelAuthenticationIssueResponse;
import com.authlete.common.dto.BackchannelAuthenticationRequest;
import com.authlete.common.dto.BackchannelAuthenticationResponse;
import com.authlete.common.web.BasicCredentials;
import com.lattice.oidc.http.AuthleteController;
import com.lattice.oidc.http.Jsons;
import com.lattice.oidc.http.Requests;
import com.lattice.oidc.http.Responses;
import com.lattice.oidc.http.WebException;
import com.lattice.oidc.user.User;
import com.lattice.oidc.user.UserStore;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import javax.inject.Inject;
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
public final class CibaController extends AuthleteController {

  private static final String CHALLENGE = "Basic realm=\"backchannel/authentication\"";

  private final UserStore users;
  private final CibaService ciba;

  @Inject
  public CibaController(UserStore users, CibaService ciba) {
    this.users = users;
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
          BackchannelAuthenticationResponse ba =
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
          if (ba.getAttestationChallenge() != null) {
            headers.put("OAuth-Client-Attestation-Challenge", ba.getAttestationChallenge());
          }
          String content = ba.getResponseContent();
          return switch (ba.getAction()) {
            // Process user identification.
            case USER_IDENTIFICATION -> identify(ba, headers);
            // 400 Bad Request
            case BAD_REQUEST -> Responses.badRequest(content, headers);
            // 401 Unauthorized
            case UNAUTHORIZED -> Responses.unauthorized(content, CHALLENGE, headers);
            // 500 Internal Server Error
            case INTERNAL_SERVER_ERROR -> Responses.serverError(content, headers);
            // This never happens.
            default -> throw unknownAction("/backchannel/authentication", ba.getAction());
          };
        });
  }

  /**
   * Identifies the end-user, validates the request further, issues an {@code auth_req_id} and starts
   * communicating with the authentication device.
   */
  private Result identify(BackchannelAuthenticationResponse ba, Map<String, String> headers) {
    // Identify a user based on the hint contained in the backchannel authentication request. If no
    // user can be identified by the hint, the request fails with "unknown_user_id".
    User user = userByHint(ba).orElseThrow(() -> fail(ba.getTicket(), Reason.UNKNOWN_USER_ID));
    // Check the expiration of the login hint token if necessary. login_hint_token formats are
    // deployment-specific; none is accepted by default, so such requests fail as expired.
    if (ba.getHintType() == com.authlete.common.types.UserIdentificationHintType.LOGIN_HINT_TOKEN) {
      // login_hint_token formats are deployment-specific; none is accepted by default.
      throw fail(ba.getTicket(), Reason.EXPIRED_LOGIN_HINT_TOKEN);
    }
    // Check the user code contained in the backchannel authentication request if necessary
    // (backchannel_user_code_parameter). The user code is stored as the "code" attribute of the user.
    if (ba.isUserCodeRequired()) {
      Object code = user.getAttribute("code");
      if (!(code instanceof String c) || !c.equals(ba.getUserCode())) {
        throw fail(ba.getTicket(), Reason.INVALID_USER_CODE);
      }
    }
    // Check the binding message in the backchannel authentication request if necessary. It must be
    // short and printable because it is displayed on both the consumption and authentication devices.
    String bindingMessage = ba.getBindingMessage();
    if (bindingMessage != null && (bindingMessage.length() > 128 || bindingMessage.chars().anyMatch(Character::isISOControl))) {
      throw fail(ba.getTicket(), Reason.INVALID_BINDING_MESSAGE);
    }

    // Issue an 'auth_req_id' by calling Authlete's /api/backchannel/authentication/issue API.
    BackchannelAuthenticationIssueResponse issue =
        api().backchannelAuthenticationIssue(new BackchannelAuthenticationIssueRequest().setTicket(ba.getTicket()));
    return switch (issue.getAction()) {
      // 200 OK. Start communicating with the authentication device for end-user authentication and
      // authorization (in the background).
      case OK -> {
        ciba.start(user, ba, issue);
        yield Responses.ok(issue.getResponseContent(), headers);
      }
      // 500 Internal Server Error (INTERNAL_SERVER_ERROR, INVALID_TICKET)
      default -> Responses.serverError(issue.getResponseContent(), headers);
    };
  }

  /**
   * Gets a user by the hint. A {@code login_hint} may be a subject, an email address or a phone
   * number; for an {@code id_token_hint}, Authlete has already validated the ID token and extracted
   * its subject.
   */
  private Optional<User> userByHint(BackchannelAuthenticationResponse ba) {
    if (ba.getHintType() == null) {
      return Optional.empty();
    }
    String hint = ba.getHint();
    return switch (ba.getHintType()) {
      case LOGIN_HINT ->
          users.bySubject(hint).or(() -> users.byEmail(hint)).or(() -> users.byPhoneNumber(hint));
      case ID_TOKEN_HINT -> users.bySubject(ba.getSub());
      default -> Optional.empty();
    };
  }

  /**
   * Generates an error response by calling Authlete's /api/backchannel/authentication/fail API.
   */
  private WebException fail(String ticket, Reason reason) {
    BackchannelAuthenticationFailResponse r =
        api().backchannelAuthenticationFail(new BackchannelAuthenticationFailRequest().setTicket(ticket).setReason(reason));
    String content = r.getResponseContent();
    return new WebException(
        switch (r.getAction()) {
          case BAD_REQUEST -> Responses.badRequest(content);
          case FORBIDDEN -> Responses.forbidden(content, null);
          default -> Responses.serverError(content);
        });
  }

  /**
   * The callback endpoint called back from the authentication device when it is used in asynchronous
   * mode. The result of the end-user authentication and authorization is expected to be contained in
   * the request. It is assumed that this server has made a request to the authentication device in
   * {@link CibaService#start} before this endpoint is called back.
   */
  @BodyParser.Of(BodyParser.TolerantText.class)
  public CompletionStage<Result> callback(Http.Request request) {
    String body = request.body().asText();
    return async(
        () -> {
          Map<String, Object> json;
          try {
            json = Jsons.readMap(body);
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

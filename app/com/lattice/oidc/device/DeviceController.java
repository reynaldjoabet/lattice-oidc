package com.lattice.oidc.device;

import com.authlete.common.dto.DeviceAuthorizationRequest;
import com.authlete.common.dto.DeviceAuthorizationResponse;
import com.authlete.common.dto.DeviceCompleteRequest;
import com.authlete.common.dto.DeviceCompleteResponse;
import com.authlete.common.dto.DeviceVerificationRequest;
import com.authlete.common.dto.DeviceVerificationResponse;
import com.authlete.common.dto.Scope;
import com.authlete.common.web.BasicCredentials;
import com.lattice.oidc.authorization.Pages;
import com.lattice.oidc.claims.ClaimsCollector;
import com.lattice.oidc.config.LatticeConfig;
import com.lattice.oidc.http.AuthleteController;
import com.lattice.oidc.http.Requests;
import com.lattice.oidc.http.Responses;
import com.lattice.oidc.session.Interactions;
import com.lattice.oidc.session.UserSessions;
import com.lattice.oidc.session.UserSessions.LoginState;
import com.lattice.oidc.user.LoginService;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import javax.inject.Inject;
import play.mvc.Http;
import play.mvc.Result;

/**
 * An implementation of OAuth 2.0 Device Authorization Grant (Device Flow).
 *
 * <ul>
 *   <li>{@code POST /api/device/authorization}: the device authorization endpoint.
 *   <li>{@code GET|POST /api/device/verification}: the verification endpoint, where the end-user
 *       logs in (if not authenticated) and inputs the user code.
 *   <li>{@code POST /api/device/complete}: receives the end-user's decision from the authorization
 *       page.
 * </ul>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8628.html">RFC 8628: OAuth 2.0 Device Authorization Grant</a>
 */
public final class DeviceController extends AuthleteController {

  private static final String CHALLENGE = "Basic realm=\"device/authorization\"";
  private static final String KIND = "device";

  /** Shown on the approval page and kept until the user decides. */
  public record Approval(
      String userCode, String clientName, List<String> scopes, String[] claimNames, String[] acrs) {}

  private final UserSessions sessions;
  private final Interactions interactions;
  private final LoginService login;
  private final LatticeConfig config;

  @Inject
  public DeviceController(
      UserSessions sessions, Interactions interactions, LoginService login, LatticeConfig config) {
    this.sessions = sessions;
    this.interactions = interactions;
    this.login = login;
    this.config = config;
  }

  /**
   * The device authorization endpoint.
   */
  public CompletionStage<Result> authorization(Http.Request request) {
    return async(
        () -> {
          BasicCredentials basic = Requests.basicCredentials(request);
          String[] chain = requests.clientCertificateChain(request);
          // Call Authlete's /api/device/authorization API.
          DeviceAuthorizationResponse r =
              api()
                  .deviceAuthorization(
                      new DeviceAuthorizationRequest()
                          .setParameters(Requests.encode(Requests.form(request)))
                          .setClientId(basic == null ? null : basic.getUserId())
                          .setClientSecret(basic == null ? null : basic.getPassword())
                          .setClientCertificate(chain == null ? null : chain[0])
                          .setClientCertificatePath(
                              chain == null || chain.length < 2 ? null : Arrays.copyOfRange(chain, 1, chain.length))
                          .setOauthClientAttestation(Requests.header(request, "OAuth-Client-Attestation"))
                          .setOauthClientAttestationPop(Requests.header(request, "OAuth-Client-Attestation-PoP")));
          Map<String, String> headers = new LinkedHashMap<>();
          if (r.getAttestationChallenge() != null) {
            headers.put("OAuth-Client-Attestation-Challenge", r.getAttestationChallenge());
          }
          String content = r.getResponseContent();
          return switch (r.getAction()) {
            // 200 OK
            case OK -> Responses.ok(content, headers);
            // 400 Bad Request
            case BAD_REQUEST -> Responses.badRequest(content, headers);
            // 401 Unauthorized
            case UNAUTHORIZED -> Responses.unauthorized(content, CHALLENGE, headers);
            // 500 Internal Server Error
            case INTERNAL_SERVER_ERROR -> Responses.serverError(content, headers);
            // This never happens.
            default -> throw unknownAction("/device/authorization", r.getAction());
          };
        });
  }

  /**
   * The verification endpoint for the {@code GET} method. Returns a verification page where the
   * end-user is asked to input their login credentials (if not authenticated) and a user code. The
   * {@code user_code} query parameter (verification_uri_complete) pre-fills the code.
   */
  public Result verificationPage(Http.Request request) {
    Optional<String> user = sessions.current(request).map(s -> s.user().displayName());
    String userCode = request.queryString("user_code").orElse("");
    return page(request, 200, userCode, user, Optional.empty());
  }

  /**
   * The verification endpoint for the {@code POST} method. Receives a request from the form in the
   * verification page.
   */
  public CompletionStage<Result> verify(Http.Request request) {
    return async(
        () -> {
          Map<String, String[]> form = Requests.form(request);
          String userCode = Optional.ofNullable(Requests.first(form, "userCode")).orElse("").trim();
          Map<String, String> sessionOut = new HashMap<>();
          Optional<LoginState> current = sessions.current(request);
          Optional<String> shown = current.map(s -> s.user().displayName());
          if (current.isEmpty()) {
            LoginService.Result auth =
                login.authenticate(Requests.first(form, "loginId"), Requests.first(form, "password"));
            if (auth.outcome() != LoginService.Outcome.SUCCESS) {
              String message =
                  auth.outcome() == LoginService.Outcome.LOCKED
                      ? "Too many failed attempts. Try again later."
                      : "Invalid login ID or password.";
              return page(request, 401, userCode, Optional.empty(), Optional.of(message));
            }
            sessions.login(auth.user().get(), System.currentTimeMillis() / 1000L, null, sessionOut);
            shown = Optional.of(auth.user().get().displayName());
          }

          // Call Authlete's /api/device/verification API.
          DeviceVerificationResponse r =
              api().deviceVerification(new DeviceVerificationRequest().setUserCode(userCode));
          Result result =
              switch (r.getAction()) {
                // The user code is valid. Ask the user to authorize the client.
                case VALID -> approvalPage(request, userCode, r);
                // The user code has expired. Urge the user to re-initiate device flow.
                case EXPIRED -> page(request, 400, "", shown, Optional.of("The code has expired. Restart on your device."));
                // The user code does not exist. Urge the user to re-input a valid user code.
                case NOT_EXIST -> page(request, 404, userCode, shown, Optional.of("The code does not exist."));
                // An error occurred on Authlete. Urge the user to re-initiate device flow.
                case SERVER_ERROR -> Pages.message(request, 500, "Error", "Please try again later.");
                // This never happens.
                default -> throw unknownAction("/device/verification", r.getAction());
              };
          return sessions.apply(result, request, sessionOut);
        });
  }

  private Result approvalPage(Http.Request request, String userCode, DeviceVerificationResponse info) {
    List<String> scopes =
        info.getScopes() == null ? List.of() : Arrays.stream(info.getScopes()).map(Scope::getName).toList();
    String clientName =
        info.getClientName() != null
            ? info.getClientName()
            : info.isClientIdAliasUsed() ? info.getClientIdAlias() : String.valueOf(info.getClientId());
    Approval approval = new Approval(userCode, clientName, scopes, info.getClaimNames(), info.getAcrs());
    String bid = sessions.bid(request);
    interactions.put(KIND, userCode, bid, approval);
    return sessions.withBid(
        Responses.of(200, views.html.oidc.deviceAuthorization.render(approval, request).body(), Responses.HTML, null),
        request,
        bid);
  }

  /**
   * Processes a request from the form in the authorization page of the Device Flow: approve or deny.
   */
  public CompletionStage<Result> complete(Http.Request request) {
    return async(
        () -> {
          Map<String, String[]> form = Requests.form(request);
          String userCode = Requests.first(form, "userCode");
          String bid = request.session().get("bid").orElse(null);
          Optional<Approval> approval = interactions.take(KIND, userCode, bid, Approval.class);
          Optional<LoginState> current = sessions.current(request);
          if (approval.isEmpty() || current.isEmpty()) {
            return Pages.message(request, 400, "Request expired", "Please enter the code again.");
          }
          boolean authorized = form.containsKey("authorized");
          DeviceCompleteRequest req =
              new DeviceCompleteRequest()
                  .setUserCode(userCode)
                  .setResult(authorized ? DeviceCompleteRequest.Result.AUTHORIZED : DeviceCompleteRequest.Result.ACCESS_DENIED);
          if (authorized) {
            LoginState s = current.get();
            req.setSubject(s.user().getSubject()).setAuthTime(s.authTime()).setAcr(acr(approval.get().acrs()));
            Map<String, Object> claims = new ClaimsCollector(s.user()).collect(approval.get().claimNames(), null);
            if (claims != null) {
              req.setClaims(claims);
            }
          }
          // Call Authlete's /api/device/complete API. On authorization, the subject, the authentication time,
          // the acr value that was actually used and the user's claims are passed.
          DeviceCompleteResponse r = api().deviceComplete(req);
          return switch (r.getAction()) {
            // The API call has been processed successfully.
            case SUCCESS ->
                Pages.message(
                    request,
                    200,
                    authorized ? "Device authorized" : "Request denied",
                    authorized
                        ? "You can return to your device."
                        : "The device was not given access.");
            // The user code has expired.
            case USER_CODE_EXPIRED -> Pages.message(request, 400, "Code expired", "Restart the flow on your device.");
            // The user code does not exist.
            case USER_CODE_NOT_EXIST -> Pages.message(request, 400, "Code invalid", "Restart the flow on your device.");
            // The API call was invalid, or an error occurred on Authlete side.
            case INVALID_REQUEST, SERVER_ERROR -> Pages.message(request, 500, "Error", "Please restart the flow.");
            // This never happens.
            default -> throw unknownAction("/device/complete", r.getAction());
          };
        });
  }

  private String acr(String[] requested) {
    return requested == null
        ? null
        : Arrays.stream(requested).filter(config.satisfiedAcrs()::contains).findFirst().orElse(null);
  }

  private static Result page(
      Http.Request request, int status, String userCode, Optional<String> user, Optional<String> notice) {
    return Responses.of(
        status,
        views.html.oidc.deviceVerification.render(userCode, user, notice, request).body(),
        Responses.HTML,
        null);
  }
}

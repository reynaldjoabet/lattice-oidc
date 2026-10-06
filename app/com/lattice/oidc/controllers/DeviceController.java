package com.lattice.oidc.controllers;

import com.authlete.common.dto.DeviceAuthorizationRequest;
import com.authlete.common.dto.DeviceAuthorizationResponse;
import com.authlete.common.dto.DeviceCompleteResponse;
import com.authlete.common.dto.DeviceVerificationResponse;
import com.authlete.common.web.BasicCredentials;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.handlers.DeviceHandler;
import com.lattice.oidc.models.DeviceApproval;
import com.lattice.oidc.security.AuditService;
import com.lattice.oidc.security.Interactions;
import com.lattice.oidc.security.LoginService;
import com.lattice.oidc.security.UserSessions.LoginState;
import com.lattice.oidc.security.UserSessions;
import com.lattice.oidc.stores.CounterStore;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import jakarta.inject.Inject;
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
public final class DeviceController extends BaseController {

  private static final String CHALLENGE = "Basic realm=\"device/authorization\"";
  private static final String KIND = "device";


  private final UserSessions sessions;
  private final Interactions interactions;
  private final LoginService login;
  private final DeviceHandler device;

  private final CounterStore counters;
  private final SignInFlow flow;
  private final LatticeConfig config;

  @Inject
  public DeviceController(
      UserSessions sessions,
      Interactions interactions,
      LoginService login,
      DeviceHandler device,
      CounterStore counters,
      LatticeConfig config,
      SignInFlow flow) {
    this.flow = flow;
    this.sessions = sessions;
    this.interactions = interactions;
    this.login = login;
    this.device = device;
    this.counters = counters;
    this.config = config;
  }

  /** Wrong user codes from this IP address within the window (RFC 8628 section 5.1). */
  private String guessesKey(Http.Request request) {
    return "device:ip:" + request.remoteAddress();
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
    Optional<String> user = sessions.current(request).map(loginState -> loginState.user().displayName());
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
          Optional<String> shown = current.map(loginState -> loginState.user().displayName());
          if (current.isEmpty()) {
            LoginService.Result auth =
                login.authenticate(Requests.first(form, "loginId"), Requests.first(form, "password"), request.remoteAddress());
            auditLogin(request, Requests.first(form, "loginId"), auth);
            if (auth.outcome() != LoginService.Outcome.SUCCESS) {
              String message =
                  auth.outcome() == LoginService.Outcome.LOCKED
                      ? "Too many failed attempts. Try again later."
                      : "Invalid login ID or password.";
              return page(request, 401, userCode, Optional.empty(), Optional.of(message));
            }
            if (flow.needsSecondFactor(auth.user().get())) {
              // After the code, the user comes back here and enters the device code again.
              return flow.challenge(request, auth.user().get(), "Password", false, "device", Optional.empty());
            }
            sessions.login(auth.user().get(), System.currentTimeMillis() / 1000L, null, sessionOut, request, "Password");
            shown = Optional.of(auth.user().get().displayName());
          }

          // Too many wrong codes from this IP address: refuse before asking Authlete, so user codes
          // can't be guessed.
          if (counters.count(guessesKey(request)) >= config.device().maxAttempts()) {
            return sessions.apply(
                page(request, 429, userCode, shown, Optional.of("Too many wrong codes. Try again later.")),
                request,
                sessionOut);
          }

          // Call Authlete's /api/device/verification API.
          DeviceVerificationResponse r = device.verify(userCode);
          if (r.getAction() == DeviceVerificationResponse.Action.NOT_EXIST) {
            counters.increment(guessesKey(request), config.device().window());
          }
          Result result =
              switch (r.getAction()) {
                // The user code is valid. Ask the user to authorize the client.
                case VALID -> approvalPage(request, userCode, r, sessionOut);
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

  /**
   * Shows the approval page. The pending approval is bound to the browser: to the id a sign-in in
   * this same request assigned ({@code sessionOut}), else the browser's own.
   */
  private Result approvalPage(
      Http.Request request, String userCode, DeviceVerificationResponse info, Map<String, String> sessionOut) {
    DeviceApproval approval = device.approval(userCode, info);
    String browserId =
        Optional.ofNullable(sessionOut.get(UserSessions.BROWSER_ID)).orElseGet(() -> sessions.browserId(request));
    interactions.put(KIND, userCode, browserId, approval);
    return sessions.withBrowserId(
        Responses.of(200, views.html.oidc.deviceAuthorization.render(approval, request).body(), Responses.HTML, null),
        request,
        browserId);
  }

  /**
   * Processes a request from the form in the authorization page of the Device Flow: approve or deny.
   */
  public CompletionStage<Result> complete(Http.Request request) {
    return async(
        () -> {
          Map<String, String[]> form = Requests.form(request);
          String userCode = Requests.first(form, "userCode");
          String browserId = sessions.existingBrowserId(request).orElse(null);
          Optional<DeviceApproval> approval = interactions.take(KIND, userCode, browserId, DeviceApproval.class);
          Optional<LoginState> current = sessions.current(request);
          if (approval.isEmpty() || current.isEmpty()) {
            return Pages.message(request, 400, "Request expired", "Please enter the code again.");
          }
          boolean authorized = form.containsKey("authorized");
          // Call Authlete's /api/device/complete API through the handler.
          DeviceCompleteResponse.Action action = device.complete(approval.get(), current, authorized);
          audit.record(
              request,
              authorized ? AuditService.Event.DEVICE_AUTHORIZED : AuditService.Event.DEVICE_DENIED,
              "subject",
              current.get().user().getSubject(),
              "client",
              approval.get().clientName());
          return switch (action) {
            // The API call has been processed successfully.
            case SUCCESS ->
                authorized
                    ? Pages.success(
                        request,
                        "Device connected",
                        approval.get().clientName()
                            + " can now use your account. You can return to your device; it will continue on its own.")
                    : Pages.message(request, 200, "Request denied", "The device was not given access.");
            // The user code has expired.
            case USER_CODE_EXPIRED -> Pages.message(request, 400, "Code expired", "Restart the flow on your device.");
            // The user code does not exist.
            case USER_CODE_NOT_EXIST -> Pages.message(request, 400, "Code invalid", "Restart the flow on your device.");
            // The API call was invalid, or an error occurred on Authlete side.
            case INVALID_REQUEST, SERVER_ERROR -> Pages.message(request, 500, "Error", "Please restart the flow.");
            // This never happens.
            default -> throw unknownAction("/device/complete", action);
          };
        });
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

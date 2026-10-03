package com.lattice.oidc.controllers;

import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.handlers.LogoutHandler;
import com.lattice.oidc.models.LogoutRequest;
import com.lattice.oidc.security.AuditService;
import com.lattice.oidc.security.UserSessions.LoginState;
import com.lattice.oidc.security.UserSessions;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import javax.inject.Inject;
import play.mvc.Http;
import play.mvc.Result;

/**
 * OpenID Connect RP-Initiated Logout 1.0 ({@code GET|POST /api/logout}) with Back-Channel Logout
 * 1.0 notifications. Without a valid {@code id_token_hint} for the current user the end-user is
 * asked to confirm, so third-party sites cannot silently log users out.
 *
 * @see <a href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html">OpenID Connect RP-Initiated Logout 1.0</a>
 * @see <a href="https://openid.net/specs/openid-connect-backchannel-1_0.html">OpenID Connect Back-Channel Logout 1.0</a>
 */
public final class LogoutController extends BaseController {

  private final UserSessions sessions;
  private final LogoutHandler logout;

  @Inject
  public LogoutController(UserSessions sessions, LogoutHandler logout) {
    this.sessions = sessions;
    this.logout = logout;
  }

  /** The end session endpoint for the {@code GET} method. */
  public CompletionStage<Result> get(Http.Request request) {
    Map<String, String[]> params = Requests.decode(Requests.rawQuery(request));
    return async(() -> process(request, params, false));
  }

  /** The end session endpoint for the {@code POST} method (form-encoded parameters). */
  public CompletionStage<Result> post(Http.Request request) {
    Map<String, String[]> params = Requests.form(request);
    return async(() -> process(request, params, false));
  }

  /** POST /api/logout/confirm — the user confirmed on the logout page (CSRF-protected). */
  public CompletionStage<Result> confirm(Http.Request request) {
    Map<String, String[]> params = Requests.form(request);
    return async(() -> process(request, params, params.containsKey("confirm")));
  }

  private Result process(Http.Request request, Map<String, String[]> params, boolean confirmed) {
    LogoutRequest logoutRequest;
    try {
      logoutRequest = logout.validate(params);
    } catch (LogoutHandler.InvalidLogoutRequest e) {
      return Pages.message(request, 400, "Logout failed", e.getMessage());
    }

    Optional<LoginState> current = sessions.current(request);
    if (current.isPresent() && !confirmed && !logout.hintMatches(logoutRequest, current.get())) {
      // Ask the end-user to confirm.
      return Responses.of(
          200,
          views.html.oidc.logoutConfirm.render(logoutRequest, request).body(),
          Responses.HTML,
          null);
    }

    Result result =
        logout
            .redirectUrl(logoutRequest)
            .map(Responses::location)
            .orElseGet(() -> Pages.message(request, 200, "Signed out", "You have been signed out."));
    if (current.isPresent()) {
      logout.endSession(current.get());
      audit.record(
          request,
          AuditService.Event.LOGOUT,
          "subject",
          current.get().user().getSubject(),
          "client_id",
          logoutRequest.clientId().orElse(null));
      result = sessions.logout(result, request, current.get().sid());
    }
    return result;
  }
}

package com.lattice.oidc.controllers;

import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.handlers.CibaHandler;
import com.lattice.oidc.models.CibaApproval;
import com.lattice.oidc.security.AuditService;
import com.lattice.oidc.security.Passkeys;
import com.lattice.oidc.security.UserSessions;
import com.lattice.oidc.security.UserSessions.LoginState;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import jakarta.inject.Inject;
import play.mvc.Http;
import play.mvc.Result;

/**
 * Lattice's own CIBA approval page ({@code lattice.ciba.mode = builtin}): a signed-in end-user
 * sees the sign-in requests made for them on other devices, checks the binding message and
 * approves or denies each one.
 *
 * <ul>
 *   <li>{@code GET /ciba}: the waiting requests.
 *   <li>{@code POST /ciba/decision}: approve or deny one ({@code id}, {@code approve}).
 *   <li>{@code GET /ciba/approved}: the result page after approving with a passkey.
 * </ul>
 *
 * Users who have a passkey approve with it (the passkey signs the request's details, see {@link
 * PasskeyController}); for them this form can only deny.
 */
public final class CibaApprovalController extends BaseController {

  private final UserSessions sessions;
  private final CibaHandler ciba;
  private final LatticeConfig config;
  private final Passkeys passkeys;

  @Inject
  public CibaApprovalController(UserSessions sessions, CibaHandler ciba, LatticeConfig config, Passkeys passkeys) {
    this.sessions = sessions;
    this.ciba = ciba;
    this.config = config;
    this.passkeys = passkeys;
  }

  public Result page(Http.Request request) {
    if (config.ciba().mode() != LatticeConfig.CibaMode.BUILTIN) {
      return Pages.message(request, 404, "Not available", "Sign-in requests are approved on your authentication device.");
    }
    Optional<LoginState> current = sessions.current(request);
    if (current.isEmpty()) {
      return AccountController.loginPage(request, "ciba", Optional.empty(), 200);
    }
    String subject = current.get().user().getSubject();
    return Responses.of(
        200,
        views.html.oidc.cibaApproval
            .render(ciba.pendingFor(subject), current.get().user().displayName(), passkeys.hasPasskeys(subject), request)
            .body(),
        Responses.HTML,
        null);
  }

  public Result approved(Http.Request request) {
    return Pages.success(request, "Approved", "You can continue on the other device.");
  }

  public CompletionStage<Result> decide(Http.Request request) {
    return async(
        () -> {
          Optional<LoginState> current = sessions.current(request);
          if (current.isEmpty()) {
            return Pages.message(request, 400, "Session expired", "Please sign in again.");
          }
          Map<String, String[]> form = Requests.form(request);
          boolean approve = form.containsKey("approve");
          String subject = current.get().user().getSubject();
          if (approve && passkeys.hasPasskeys(subject)) {
            return Pages.message(request, 400, "Approve with your passkey", "Go back and choose \"Approve with passkey\".");
          }
          Optional<CibaApproval> decided = ciba.decide(subject, Requests.first(form, "id"), approve);
          if (decided.isEmpty()) {
            return Pages.message(
                request,
                400,
                "Request expired",
                "This sign-in request is no longer waiting. Start again on the other device.");
          }
          audit.record(
              request,
              approve ? AuditService.Event.CIBA_APPROVED : AuditService.Event.CIBA_DENIED,
              "subject",
              subject,
              "client",
              decided.get().clientName());
          return approve
              ? Pages.success(request, "Sign-in approved", "You can continue on the other device.")
              : Pages.message(request, 200, "Request denied", decided.get().clientName() + " was not signed in.");
        });
  }
}

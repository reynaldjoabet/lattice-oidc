package com.lattice.oidc.controllers;

import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.handlers.LogoutHandler;
import com.lattice.oidc.models.User;
import com.lattice.oidc.security.AuditService;
import com.lattice.oidc.security.PasswordPolicy;
import com.lattice.oidc.security.RecoveryService;
import com.lattice.oidc.stores.UserStore;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import jakarta.inject.Inject;
import play.mvc.Http;
import play.mvc.Result;

/**
 * Forgotten password (screens 30 to 33).
 *
 * <ul>
 *   <li>{@code GET|POST /account/recover}: ask for a reset link by email or login ID. The answer
 *       is the same whether or not an account matched.
 *   <li>{@code GET|POST /account/reset}: choose a new password with the link's {@code token}; by
 *       default every session of the account ends, with back-channel logout to its apps.
 * </ul>
 *
 * {@code next} (account, ciba, admin or authz:&lt;ticket&gt;) is where "Sign in" leads afterwards.
 */
public final class RecoveryController extends BaseController {

  private final RecoveryService recovery;
  private final UserStore users;
  private final LogoutHandler logout;

  @Inject
  public RecoveryController(RecoveryService recovery, UserStore users, LogoutHandler logout) {
    this.recovery = recovery;
    this.users = users;
    this.logout = logout;
  }

  public Result form(Http.Request request, String next) {
    return page(200, views.html.oidc.recoverForm.render(PasskeyController.safeNext(next), request).body());
  }

  public CompletionStage<Result> send(Http.Request request) {
    return async(
        () -> {
          Map<String, String[]> form = Requests.form(request);
          String next = PasskeyController.safeNext(Requests.first(form, "next"));
          String identifier = Requests.first(form, "identifier");
          String base = requests.baseUrl(request);
          boolean sent =
              recovery.request(
                  identifier,
                  next,
                  request.remoteAddress(),
                  token -> base + com.lattice.oidc.controllers.routes.RecoveryController.resetForm(token).url());
          audit.record(request, AuditService.Event.PASSWORD_RESET_REQUESTED, "sent", sent);
          return page(
              200,
              views.html.oidc.recoverSent.render(next, recovery.linkLifetimeMinutes(), request).body());
        });
  }

  public Result resetForm(Http.Request request, String token) {
    Optional<RecoveryService.Pending> pending = recovery.peek(token);
    Optional<User> user = pending.flatMap(found -> users.bySubject(found.subject()));
    if (user.isEmpty()) {
      return expired(request);
    }
    return page(200, views.html.oidc.resetForm.render(token, user.get().displayName(), List.of(), request).body());
  }

  public CompletionStage<Result> reset(Http.Request request) {
    return async(
        () -> {
          Map<String, String[]> form = Requests.form(request);
          String token = Requests.first(form, "token");
          Optional<RecoveryService.Pending> pending = recovery.peek(token);
          Optional<User> user = pending.flatMap(found -> users.bySubject(found.subject()));
          if (user.isEmpty()) {
            return expired(request);
          }
          String password = Optional.ofNullable(Requests.first(form, "password")).orElse("");
          List<String> problems = new java.util.ArrayList<>(PasswordPolicy.problems(password, user.get()));
          if (!password.equals(Requests.first(form, "confirmation"))) {
            problems.add("The two passwords don't match.");
          }
          if (!problems.isEmpty()) {
            return page(
                400, views.html.oidc.resetForm.render(token, user.get().displayName(), problems, request).body());
          }
          Optional<User> updated = recovery.reset(token, password);
          if (updated.isEmpty()) {
            return expired(request);
          }
          boolean signOutEverywhere = form.containsKey("signOutEverywhere");
          if (signOutEverywhere) {
            logout.endSessionsOf(updated.get(), null);
          }
          audit.record(
              request,
              AuditService.Event.PASSWORD_CHANGED,
              "subject",
              updated.get().getSubject(),
              "signed_out_everywhere",
              signOutEverywhere);
          return page(
              200,
              views.html.oidc.resetDone
                  .render(PasskeyController.url(pending.get().next()), signOutEverywhere, request)
                  .body());
        });
  }

  private Result expired(Http.Request request) {
    return page(400, views.html.oidc.resetExpired.render(request).body());
  }

  /** Reset pages carry the token: never cached, never sent on as a referrer. */
  private static Result page(int status, String html) {
    return Responses.of(status, html, Responses.HTML, null)
        .withHeader(CACHE_CONTROL, "no-store")
        .withHeader("Referrer-Policy", "no-referrer");
  }
}

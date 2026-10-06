package com.lattice.oidc.controllers;

import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.models.UiSettings;
import com.lattice.oidc.models.User;
import com.lattice.oidc.security.AuditService;
import com.lattice.oidc.security.EmailVerification;
import com.lattice.oidc.security.PasswordPolicy;
import com.lattice.oidc.security.RequiredActions;
import com.lattice.oidc.security.RequiredActions.Action;
import com.lattice.oidc.security.UserSessions;
import com.lattice.oidc.security.UserSessions.LoginState;
import com.lattice.oidc.stores.UserStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;
import jakarta.inject.Inject;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;

/**
 * Required actions ({@link RequiredActions}): what a signed-in user must do before continuing.
 *
 * <ul>
 *   <li>{@code GET /account/actions?next=...}: the first pending action, or on to {@code next} when
 *       none is left.
 *   <li>{@code POST /account/actions/verify-email}: send a verification link; {@code GET
 *       /account/verify-email?token=...} opens it (signed in or not).
 *   <li>{@code POST /account/actions/terms}: accept (or decline, which signs out) the terms.
 *   <li>{@code POST /account/actions/password}: choose a new password.
 * </ul>
 *
 * Setting up an authenticator app ({@link SecondFactorController}) or a passkey ({@link
 * PasskeyController}) completes the other two actions.
 */
public final class RequiredActionsController extends BaseController {

  private final UserSessions sessions;
  private final RequiredActions actions;
  private final EmailVerification emails;
  private final UserStore users;

  @Inject
  public RequiredActionsController(
      UserSessions sessions, RequiredActions actions, EmailVerification emails, UserStore users) {
    this.sessions = sessions;
    this.actions = actions;
    this.emails = emails;
    this.users = users;
  }

  public CompletionStage<Result> page(Http.Request request, String next) {
    return signedIn(
        request,
        state -> {
          String safe = PasskeyController.safeNext(next);
          List<Action> pending = actions.pending(state.user());
          if (pending.isEmpty()) {
            return Results.seeOther(PasskeyController.url(safe));
          }
          return show(request, state.user(), pending.get(0), safe, Optional.empty(), 200);
        });
  }

  private Result show(Http.Request request, User user, Action action, String next, Optional<String> message, int status) {
    String html =
        switch (action) {
          case VERIFY_EMAIL -> views.html.oidc.requiredVerifyEmail.render(user.email().orElse(""), next, message, request).body();
          case TERMS_AND_CONDITIONS ->
              views.html.oidc.requiredTerms.render(UiSettings.of(request).termsUrl(), actions.termsVersion(), next, request).body();
          case UPDATE_PASSWORD -> views.html.oidc.requiredPassword.render(next, message.map(List::of).orElse(List.of()), request).body();
          case CONFIGURE_PASSKEY -> views.html.oidc.requiredPasskey.render(next, request).body();
          case CONFIGURE_TOTP -> null;
        };
    if (html == null) {
      return Results.seeOther(com.lattice.oidc.controllers.routes.SecondFactorController.setupPage(next));
    }
    return Responses.of(status, html, Responses.HTML, null).withHeader(CACHE_CONTROL, "no-store");
  }

  // ---------------------------------------------------------------- verify email

  public CompletionStage<Result> sendVerification(Http.Request request) {
    return signedIn(
        request,
        state -> {
          String next = PasskeyController.safeNext(Requests.first(Requests.form(request), "next"));
          String base = requests.baseUrl(request);
          boolean sent =
              emails.send(
                  state.user(),
                  token -> base + com.lattice.oidc.controllers.routes.RequiredActionsController.verifyEmail(token).url());
          return show(
              request,
              state.user(),
              Action.VERIFY_EMAIL,
              next,
              Optional.of(sent ? "We've sent a new link. It works for 24 hours." : "Please wait a few minutes before asking for another link."),
              sent ? 200 : 429);
        });
  }

  public CompletionStage<Result> verifyEmail(Http.Request request, String token) {
    return async(
        () -> {
          Optional<User> verified = emails.verify(token);
          if (verified.isEmpty()) {
            return Pages.message(request, 400, "Link expired", "This link has expired or was already used. Sign in to get a new one.");
          }
          audit.record(request, AuditService.Event.EMAIL_VERIFIED, "subject", verified.get().getSubject());
          return Pages.success(request, "Email verified", "Thanks. You can go back to where you were signing in.");
        });
  }

  // ---------------------------------------------------------------- terms

  public CompletionStage<Result> terms(Http.Request request) {
    return signedIn(
        request,
        state -> {
          Map<String, String[]> form = Requests.form(request);
          String next = PasskeyController.safeNext(Requests.first(form, "next"));
          if (!form.containsKey("accept")) {
            audit.record(request, AuditService.Event.TERMS_DECLINED, "subject", state.user().getSubject());
            return sessions.logout(
                Pages.message(request, 200, "Signed out", "You need to accept the terms to use your account."),
                request,
                state.sessionId());
          }
          actions.acceptTerms(state.user());
          audit.record(request, AuditService.Event.TERMS_ACCEPTED, "subject", state.user().getSubject(), "version", actions.termsVersion());
          return Results.seeOther(SignInFlow.actionsUrl(next));
        });
  }

  // ---------------------------------------------------------------- new password

  public CompletionStage<Result> password(Http.Request request) {
    return signedIn(
        request,
        state -> {
          Map<String, String[]> form = Requests.form(request);
          String next = PasskeyController.safeNext(Requests.first(form, "next"));
          User user = state.user();
          String password = Optional.ofNullable(Requests.first(form, "password")).orElse("");
          List<String> problems = new ArrayList<>(PasswordPolicy.problems(password, user));
          if (!password.equals(Requests.first(form, "confirmation"))) {
            problems.add("The two passwords don't match.");
          }
          if (!problems.isEmpty()) {
            return Responses.of(
                    400, views.html.oidc.requiredPassword.render(next, problems, request).body(), Responses.HTML, null)
                .withHeader(CACHE_CONTROL, "no-store");
          }
          users.save(actions.cleared(user.withPasswordHash(PasswordPolicy.hash(password)), Action.UPDATE_PASSWORD));
          audit.record(request, AuditService.Event.PASSWORD_CHANGED, "subject", user.getSubject(), "required_action", true);
          return Results.seeOther(SignInFlow.actionsUrl(next));
        });
  }

  private CompletionStage<Result> signedIn(Http.Request request, Function<LoginState, Result> action) {
    return async(
        () -> {
          Optional<LoginState> current = sessions.current(request);
          if (current.isEmpty()) {
            return AccountController.loginPage(request, "account", Optional.empty(), 200);
          }
          return action.apply(current.get());
        });
  }
}

package com.lattice.oidc.controllers;

import com.authlete.common.dto.Client;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.handlers.LogoutHandler;
import com.lattice.oidc.models.User;
import com.lattice.oidc.security.AuditService;
import com.lattice.oidc.security.LoginService;
import com.lattice.oidc.security.PasswordPolicy;
import com.lattice.oidc.security.SignInAlerts;
import com.lattice.oidc.security.UserSessions;
import com.lattice.oidc.security.UserSessions.LoginState;
import com.lattice.oidc.security.UserSessions.SessionInfo;
import com.lattice.oidc.stores.UserStore;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;
import javax.inject.Inject;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;

/**
 * Account security for the signed-in user (screens 25, 26 and 29).
 *
 * <ul>
 *   <li>{@code GET /account/sessions}: where the account is signed in.
 *   <li>{@code POST /account/sessions/:id/end}: sign out one other session.
 *   <li>{@code GET|POST /account/sessions/others}: sign out everywhere else, after listing the apps
 *       that will be told (back-channel logout); optionally continue to change the password.
 *   <li>{@code POST /account/alerts/:id}: answer a "new sign-in" alert. "No" ends that session and
 *       continues to change the password.
 *   <li>{@code GET|POST /account/password}: change the password (current one required).
 * </ul>
 */
public final class AccountSecurityController extends BaseController {

  private final UserSessions sessions;
  private final LogoutHandler logout;
  private final SignInAlerts alerts;
  private final LoginService login;
  private final UserStore users;

  @Inject
  public AccountSecurityController(
      UserSessions sessions, LogoutHandler logout, SignInAlerts alerts, LoginService login, UserStore users) {
    this.sessions = sessions;
    this.logout = logout;
    this.alerts = alerts;
    this.login = login;
    this.users = users;
  }

  /** A session as shown: which apps were used there, by name. */
  public record SessionView(SessionInfo session, boolean current, List<String> apps) {}

  // ---------------------------------------------------------------- sessions

  public CompletionStage<Result> sessions(Http.Request request) {
    return signedIn(
        request,
        state -> {
          Function<String, String> names = clientNames();
          List<SessionView> shown = new ArrayList<>();
          for (SessionInfo session : sessions.sessionsOf(state.user().getSubject())) {
            shown.add(
                new SessionView(
                    session,
                    session.sessionId().equals(state.sessionId()),
                    session.clients().stream().map(names).toList()));
          }
          shown.sort((left, right) -> Boolean.compare(right.current(), left.current()));
          return html(200, views.html.oidc.sessions.render(shown, request).body());
        });
  }

  public CompletionStage<Result> endSession(Http.Request request, String id) {
    return signedIn(
        request,
        state -> {
          if (!id.equals(state.sessionId())) {
            sessions
                .sessionOf(state.user().getSubject(), id)
                .ifPresent(
                    session -> {
                      logout.endSession(new LoginState(state.user(), id, 0L, null));
                      sessions.end(id);
                      audit.record(request, AuditService.Event.SESSION_ENDED, "subject", state.user().getSubject());
                    });
          }
          return Results.seeOther(com.lattice.oidc.controllers.routes.AccountSecurityController.sessions());
        });
  }

  public CompletionStage<Result> othersPage(Http.Request request) {
    return signedIn(
        request,
        state -> {
          List<SessionInfo> others = others(state);
          if (others.isEmpty()) {
            return Results.seeOther(com.lattice.oidc.controllers.routes.AccountSecurityController.sessions());
          }
          Set<String> clients = new LinkedHashSet<>();
          others.forEach(session -> clients.addAll(session.clients()));
          return html(200, views.html.oidc.signOutOthers.render(others.size(), names(clients), request).body());
        });
  }

  public CompletionStage<Result> endOthers(Http.Request request) {
    return signedIn(
        request,
        state -> {
          logout.endSessionsOf(state.user(), state.sessionId());
          audit.record(request, AuditService.Event.SESSION_ENDED, "subject", state.user().getSubject(), "scope", "others");
          return Requests.form(request).containsKey("changePassword")
              ? Results.seeOther(com.lattice.oidc.controllers.routes.AccountSecurityController.passwordForm())
              : Results.seeOther(com.lattice.oidc.controllers.routes.AccountSecurityController.sessions());
        });
  }

  // ---------------------------------------------------------------- alerts

  public CompletionStage<Result> answerAlert(Http.Request request, String id) {
    return signedIn(
        request,
        state -> {
          String subject = state.user().getSubject();
          Optional<SignInAlerts.Alert> alert = alerts.resolve(subject, id);
          if (alert.isEmpty() || !"no".equals(Requests.first(Requests.form(request), "answer"))) {
            return Results.seeOther(AccountController.DESTINATIONS.get("account"));
          }
          String sessionId = alert.get().sessionId();
          if (!sessionId.equals(state.sessionId()) && sessions.sessionOf(subject, sessionId).isPresent()) {
            logout.endSession(new LoginState(state.user(), sessionId, 0L, null));
            sessions.end(sessionId);
          }
          audit.record(request, AuditService.Event.SIGN_IN_REPORTED, "subject", subject, "ip", alert.get().ip());
          return Results.seeOther(com.lattice.oidc.controllers.routes.AccountSecurityController.passwordForm());
        });
  }

  // ---------------------------------------------------------------- password

  public CompletionStage<Result> passwordForm(Http.Request request) {
    return signedIn(request, state -> passwordPage(request, state.user(), List.of(), 200));
  }

  public CompletionStage<Result> changePassword(Http.Request request) {
    return signedIn(
        request,
        state -> {
          User user = state.user();
          if (user.passwordHash() == null) {
            return passwordPage(request, user, List.of(), 400);
          }
          Map<String, String[]> form = Requests.form(request);
          LoginService.Result check = login.authenticate(user.loginId(), Requests.first(form, "current"), request.remoteAddress());
          auditLogin(request, user.loginId(), check);
          if (check.outcome() != LoginService.Outcome.SUCCESS) {
            return passwordPage(request, user, List.of(AuthorizationController.failureMessage(check)), 401);
          }
          String password = Optional.ofNullable(Requests.first(form, "password")).orElse("");
          List<String> problems = new ArrayList<>(PasswordPolicy.problems(password, user));
          if (!password.equals(Requests.first(form, "confirmation"))) {
            problems.add("The two passwords don't match.");
          }
          if (!problems.isEmpty()) {
            return passwordPage(request, user, problems, 400);
          }
          User updated = user.withPasswordHash(PasswordPolicy.hash(password));
          users.save(updated);
          boolean signOutEverywhere = form.containsKey("signOutEverywhere");
          if (signOutEverywhere) {
            logout.endSessionsOf(updated, state.sessionId());
          }
          audit.record(
              request,
              AuditService.Event.PASSWORD_CHANGED,
              "subject",
              user.getSubject(),
              "signed_out_everywhere",
              signOutEverywhere);
          return Pages.success(
              request,
              "Password changed",
              signOutEverywhere
                  ? "Your other devices and apps have been signed out."
                  : "Use your new password next time you sign in.");
        });
  }

  private Result passwordPage(Http.Request request, User user, List<String> problems, int status) {
    return html(status, views.html.oidc.changePassword.render(user.passwordHash() != null, problems, request).body());
  }

  // ---------------------------------------------------------------- helpers

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

  private List<SessionInfo> others(LoginState state) {
    return sessions.sessionsOf(state.user().getSubject()).stream()
        .filter(session -> !session.sessionId().equals(state.sessionId()))
        .toList();
  }

  private List<String> names(Collection<String> clientIdentifiers) {
    Function<String, String> names = clientNames();
    return clientIdentifiers.stream().map(names).distinct().toList();
  }

  /** Client identifier to display name (Authlete), falling back to the identifier. */
  private Function<String, String> clientNames() {
    Map<String, String> known = new java.util.HashMap<>();
    return identifier ->
        known.computeIfAbsent(
            identifier,
            key -> {
              try {
                Client client = api().getClient(key);
                return client != null && client.getClientName() != null ? client.getClientName() : key;
              } catch (RuntimeException e) {
                return key;
              }
            });
  }

  private static Result html(int status, String body) {
    return Responses.of(status, body, Responses.HTML, null).withHeader(CACHE_CONTROL, "no-store");
  }
}

package com.lattice.oidc.controllers;

import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.models.User;
import com.lattice.oidc.security.AuditService;
import com.lattice.oidc.security.Interactions;
import com.lattice.oidc.security.LoginService;
import com.lattice.oidc.security.SecondFactors;
import com.lattice.oidc.security.SecretCipher;
import com.lattice.oidc.security.UserSessions;
import com.lattice.oidc.security.UserSessions.LoginState;
import com.lattice.oidc.stores.CounterStore;
import com.lattice.oidc.stores.IdentityLinkStore;
import com.lattice.oidc.stores.UserStore;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import javax.inject.Inject;
import play.mvc.Http;
import play.mvc.Result;

/**
 * Authenticator apps (TOTP) and recovery codes.
 *
 * <ul>
 *   <li>{@code POST /sign-in/code}: the second step of a password sign-in, with a code from the
 *       app or a recovery code ({@link SignInFlow#challenge}).
 *   <li>{@code GET|POST /account/two-step}: set up an authenticator app (scan the QR code, enter a
 *       code to confirm); new recovery codes are shown once.
 *   <li>{@code POST /account/two-step/remove}, {@code POST /account/recovery-codes}: remove the app,
 *       or replace the recovery codes, after confirming it's you.
 * </ul>
 *
 * Wrong codes count against the account: after {@code lattice.login.max-failures} within {@code
 * lattice.login.lockout}, the pending sign-in is dropped and must start again.
 */
public final class SecondFactorController extends BaseController {

  private static final String SETUP = "totp-setup";

  private final SignInFlow flow;
  private final SecondFactors secondFactors;
  private final UserSessions sessions;
  private final Interactions interactions;
  private final UserStore users;
  private final IdentityLinkStore links;
  private final CounterStore counters;
  private final LoginService login;
  private final SecretCipher cipher;
  private final LatticeConfig config;

  @Inject
  public SecondFactorController(
      SignInFlow flow,
      SecondFactors secondFactors,
      UserSessions sessions,
      Interactions interactions,
      UserStore users,
      IdentityLinkStore links,
      CounterStore counters,
      LoginService login,
      SecretCipher cipher,
      LatticeConfig config) {
    this.flow = flow;
    this.secondFactors = secondFactors;
    this.sessions = sessions;
    this.interactions = interactions;
    this.users = users;
    this.links = links;
    this.counters = counters;
    this.login = login;
    this.cipher = cipher;
    this.config = config;
  }

  // ---------------------------------------------------------------- sign-in

  public CompletionStage<Result> verify(Http.Request request) {
    return async(
        () -> {
          Map<String, String[]> form = Requests.form(request);
          String id = Requests.first(form, "id");
          String browserId = sessions.existingBrowserId(request).orElse(null);
          Optional<SignInFlow.Pending> pending =
              interactions.get(SignInFlow.SECOND_FACTOR, id, browserId, SignInFlow.Pending.class);
          Optional<User> user = pending.flatMap(found -> users.bySubject(found.subject()));
          if (user.isEmpty()) {
            return Pages.message(request, 400, "Sign-in expired", "Please sign in again.");
          }
          String subject = user.get().getSubject();
          String failuresKey = "second-factor:" + subject;
          if (counters.count(failuresKey) >= config.loginMaxFailures()) {
            interactions.take(SignInFlow.SECOND_FACTOR, id, browserId, SignInFlow.Pending.class);
            audit.record(request, AuditService.Event.LOGIN_LOCKED, "subject", subject, "method", "authenticator app");
            return Pages.message(request, 429, "Too many wrong codes", "Wait a while, then sign in again.");
          }

          String code = Optional.ofNullable(Requests.first(form, "code")).orElse("");
          String recoveryCode = Optional.ofNullable(Requests.first(form, "recoveryCode")).orElse("");
          boolean usedRecoveryCode = code.isBlank() && !recoveryCode.isBlank();
          boolean accepted =
              usedRecoveryCode
                  ? secondFactors.useRecoveryCode(subject, recoveryCode)
                  : secondFactors.verifyCode(subject, code);
          if (!accepted) {
            counters.increment(failuresKey, config.loginLockout());
            audit.record(request, AuditService.Event.LOGIN_FAILED, "subject", subject, "method", "authenticator app");
            return Responses.of(
                401,
                views.html.oidc.secondFactor
                    .render(
                        id,
                        secondFactors.remainingRecoveryCodes(subject) > 0,
                        Optional.of(usedRecoveryCode ? "That recovery code isn't valid." : "That code isn't valid. Try the current one."),
                        request)
                    .body(),
                Responses.HTML,
                null);
          }

          // Single use: of two concurrent submissions, only one continues.
          if (interactions.take(SignInFlow.SECOND_FACTOR, id, browserId, SignInFlow.Pending.class).isEmpty()) {
            return Pages.message(request, 400, "Sign-in expired", "Please sign in again.");
          }
          counters.reset(failuresKey);
          SignInFlow.Pending signIn = pending.get();
          if (signIn.linkProviderId() != null) {
            links.link(signIn.linkProviderId(), signIn.linkExternalSubject(), subject);
            audit.record(request, AuditService.Event.ACCOUNT_LINKED, "subject", subject, "provider", signIn.linkProviderId());
          }
          String factor = usedRecoveryCode ? "recovery code" : "authenticator app";
          audit.record(request, AuditService.Event.LOGIN_SUCCEEDED, "subject", subject, "method", "password + " + factor);
          if (usedRecoveryCode) {
            audit.record(
                request,
                AuditService.Event.RECOVERY_CODE_USED,
                "subject",
                subject,
                "remaining",
                secondFactors.remainingRecoveryCodes(subject));
          }
          return flow.startAndRedirect(
              request, user.get(), signIn.method() + " + " + factor, secondFactors.acr(), signIn.rememberMe(), signIn.next());
        });
  }

  // ---------------------------------------------------------------- set up

  public CompletionStage<Result> setupPage(Http.Request request, String next) {
    return signedIn(
        request,
        state -> {
          SecondFactors.Enrollment enrollment = secondFactors.startEnrollment(state.user());
          // The secret waits, encrypted and bound to this browser, until a code confirms it.
          interactions.put(SETUP, state.sessionId(), sessions.browserId(request), cipher.encrypt(enrollment.secret()));
          return page(200, views.html.oidc.twoStepSetup.render(enrollment, PasskeyController.safeNext(next), Optional.empty(), request).body());
        });
  }

  public CompletionStage<Result> setup(Http.Request request) {
    return signedIn(
        request,
        state -> {
          Map<String, String[]> form = Requests.form(request);
          String next = PasskeyController.safeNext(Requests.first(form, "next"));
          String browserId = sessions.existingBrowserId(request).orElse(null);
          Optional<String> secret =
              interactions.get(SETUP, state.sessionId(), browserId, String.class).map(cipher::decrypt);
          if (secret.isEmpty()) {
            return play.mvc.Results.seeOther(com.lattice.oidc.controllers.routes.SecondFactorController.setupPage(next));
          }
          String subject = state.user().getSubject();
          if (!secondFactors.finishEnrollment(subject, secret.get(), Requests.first(form, "code"))) {
            SecondFactors.Enrollment again = secondFactors.enrollment(state.user(), secret.get());
            return page(
                400,
                views.html.oidc.twoStepSetup
                    .render(again, next, Optional.of("That code isn't valid. Enter the current code from the app."), request)
                    .body());
          }
          interactions.take(SETUP, state.sessionId(), browserId, String.class);
          audit.record(request, AuditService.Event.SECOND_FACTOR_ADDED, "subject", subject);
          List<String> codes = secondFactors.newRecoveryCodes(subject);
          return page(200, views.html.oidc.recoveryCodes.render(codes, SignInFlow.actionsUrl(next), request).body());
        });
  }

  // ---------------------------------------------------------------- remove, new recovery codes

  public CompletionStage<Result> remove(Http.Request request) {
    return signedIn(
        request,
        state -> {
          if (!confirmed(request, state)) {
            return Pages.message(request, 401, "Confirm it's you", "Enter your password (or confirm with a passkey) to remove the app.");
          }
          secondFactors.remove(state.user().getSubject());
          audit.record(request, AuditService.Event.SECOND_FACTOR_REMOVED, "subject", state.user().getSubject());
          return play.mvc.Results.seeOther(AccountController.DESTINATIONS.get("account"));
        });
  }

  public CompletionStage<Result> recoveryCodes(Http.Request request) {
    return signedIn(
        request,
        state -> {
          String subject = state.user().getSubject();
          if (!secondFactors.enrolled(subject)) {
            return play.mvc.Results.seeOther(AccountController.DESTINATIONS.get("account"));
          }
          if (!confirmed(request, state)) {
            return Pages.message(request, 401, "Confirm it's you", "Enter your password (or confirm with a passkey) to get new codes.");
          }
          audit.record(request, AuditService.Event.RECOVERY_CODES_REPLACED, "subject", subject);
          return page(
              200,
              views.html.oidc.recoveryCodes
                  .render(secondFactors.newRecoveryCodes(subject), AccountController.DESTINATIONS.get("account"), request)
                  .body());
        });
  }

  /** The password, or a passkey confirmation within the last few minutes for accounts without one. */
  private boolean confirmed(Http.Request request, LoginState state) {
    User user = state.user();
    String password = Requests.first(Requests.form(request), "password");
    if (user.passwordHash() != null) {
      if (password == null || password.isEmpty()) {
        return false;
      }
      LoginService.Result check = login.authenticate(user.loginId(), password, request.remoteAddress());
      auditLogin(request, user.loginId(), check);
      return check.outcome() == LoginService.Outcome.SUCCESS;
    }
    return interactions
        .get(PasskeyController.REAUTH, state.sessionId(), sessions.existingBrowserId(request).orElse(null), Instant.class)
        .map(at -> at.plusSeconds(PasskeyController.REAUTH_SECONDS).isAfter(Instant.now()))
        .orElse(false);
  }

  private CompletionStage<Result> signedIn(Http.Request request, java.util.function.Function<LoginState, Result> action) {
    return async(
        () -> {
          Optional<LoginState> current = sessions.current(request);
          if (current.isEmpty()) {
            return AccountController.loginPage(request, "account", Optional.empty(), 200);
          }
          return action.apply(current.get());
        });
  }

  /** Pages with secrets or codes: never cached, never sent on as a referrer. */
  private static Result page(int status, String html) {
    return Responses.of(status, html, Responses.HTML, null)
        .withHeader(CACHE_CONTROL, "no-store")
        .withHeader("Referrer-Policy", "no-referrer");
  }
}

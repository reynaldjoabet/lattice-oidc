package com.lattice.oidc.controllers;

import com.lattice.oidc.common.Responses;
import com.lattice.oidc.models.AuthorizationInteraction;
import com.lattice.oidc.models.User;
import com.lattice.oidc.security.Interactions;
import com.lattice.oidc.security.RequiredActions;
import com.lattice.oidc.security.SecondFactors;
import com.lattice.oidc.security.UserSessions;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Singleton;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;

/**
 * What happens after a user proves who they are with a first factor (a password):
 *
 * <ol>
 *   <li>if the account has an authenticator app, ask for a code ({@link #challenge}); the sign-in
 *       continues in {@link SecondFactorController};
 *   <li>start the session ({@link #start});
 *   <li>go to any pending {@link RequiredActions}, then on to {@code next}.
 * </ol>
 *
 * {@code next} is one of the fixed destinations ({@link PasskeyController#safeNext}): account,
 * ciba, admin, device, offer or authz:&lt;ticket&gt;.
 */
@Singleton
public final class SignInFlow {

  static final String SECOND_FACTOR = "second-factor";

  /**
   * A sign-in waiting for its second factor. {@code linkProviderId} and {@code linkExternalSubject}
   * are set when it also confirms linking an upstream identity.
   */
  public record Pending(
      String subject,
      String method,
      boolean rememberMe,
      String next,
      String linkProviderId,
      String linkExternalSubject) {}

  /** A started session: the values for the session cookie, and where to go next. */
  public record Started(Map<String, String> sessionOut, String destination) {}

  private final UserSessions sessions;
  private final Interactions interactions;
  private final SecondFactors secondFactors;
  private final RequiredActions actions;

  @Inject
  public SignInFlow(
      UserSessions sessions, Interactions interactions, SecondFactors secondFactors, RequiredActions actions) {
    this.sessions = sessions;
    this.interactions = interactions;
    this.secondFactors = secondFactors;
    this.actions = actions;
  }

  public boolean needsSecondFactor(User user) {
    return secondFactors.enrolled(user.getSubject());
  }

  /** Asks for a code from the authenticator app (or a recovery code) before signing in. */
  public Result challenge(
      Http.Request request, User user, String method, boolean rememberMe, String next, Optional<String[]> link) {
    String id = UserSessions.randomId();
    String browserId = sessions.browserId(request);
    interactions.put(
        SECOND_FACTOR,
        id,
        browserId,
        new Pending(
            user.getSubject(),
            method,
            rememberMe,
            PasskeyController.safeNext(next),
            link.map(pair -> pair[0]).orElse(null),
            link.map(pair -> pair[1]).orElse(null)));
    return sessions.withBrowserId(
        Responses.of(
            200,
            views.html.oidc.secondFactor
                .render(id, secondFactors.remainingRecoveryCodes(user.getSubject()) > 0, Optional.empty(), request)
                .body(),
            Responses.HTML,
            null),
        request,
        browserId);
  }

  /**
   * Starts the session for a fully authenticated user. For an authorization request, the pending
   * request now shows this user as signed in.
   */
  public Started start(
      Http.Request request, User user, String method, String acr, boolean rememberMe, String next) {
    Map<String, String> sessionOut = new HashMap<>();
    sessions.login(user, System.currentTimeMillis() / 1000L, acr, sessionOut, request, method, rememberMe);
    String safe = PasskeyController.safeNext(next);
    if (safe.startsWith("authz:")) {
      showSignedIn(safe.substring(6), sessionOut.get(UserSessions.BROWSER_ID), user);
    }
    return new Started(sessionOut, destination(user, safe));
  }

  /** As {@link #start}, answered with a redirect. */
  public Result startAndRedirect(
      Http.Request request, User user, String method, String acr, boolean rememberMe, String next) {
    Started started = start(request, user, method, acr, rememberMe, next);
    return sessions.apply(Results.seeOther(started.destination()), request, started.sessionOut());
  }

  /** Marks a pending authorization request as signed in by {@code user}. */
  void showSignedIn(String ticket, String browserId, User user) {
    interactions
        .get(AuthorizationController.KIND, ticket, browserId, AuthorizationInteraction.class)
        .ifPresent(
            interaction ->
                interactions.put(
                    AuthorizationController.KIND,
                    ticket,
                    browserId,
                    interaction
                        .withPage(interaction.page().withLoggedInAs(Optional.of(user.displayName())).withError(null))
                        .withShownSubject(user.getSubject())));
  }

  /** Where a signed-in user goes: their required actions first, otherwise {@code next}. */
  public String destination(User user, String next) {
    return actions.pending(user).isEmpty() ? PasskeyController.url(next) : actionsUrl(next);
  }

  /** A redirect to the required actions, if the user has any pending. */
  public Optional<Result> gate(User user, String next) {
    return actions.pending(user).isEmpty() ? Optional.empty() : Optional.of(Results.seeOther(actionsUrl(next)));
  }

  static String actionsUrl(String next) {
    return com.lattice.oidc.controllers.routes.RequiredActionsController.page(PasskeyController.safeNext(next)).url();
  }
}

package com.lattice.oidc.filters;

import com.lattice.oidc.security.RequiredActions;
import com.lattice.oidc.security.UserSessions;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.apache.pekko.stream.Materializer;
import play.mvc.Filter;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;

/**
 * Sends a signed-in user with pending {@link RequiredActions} to them before the account, approval,
 * console, device and credential-offer pages. The pages that complete the actions (and sign-in,
 * sign-out and recovery) stay reachable. Consent pages are gated by the authorization flow itself,
 * which knows the pending request to return to.
 */
@Singleton
public final class RequiredActionsFilter extends Filter {

  /** Gated path prefixes, and where the user continues afterwards. */
  private static final Map<String, String> GATED =
      Map.of(
          "/account", "account",
          "/ciba", "ciba",
          "/admin", "admin",
          "/api/device/verification", "device",
          "/api/device/complete", "device",
          "/api/offer/issue", "offer");

  /** Reachable even with pending actions: they complete the actions, or leave. */
  private static final List<String> ALLOWED =
      List.of(
          "/account/actions",
          "/account/verify-email",
          "/account/two-step",
          "/account/recover",
          "/account/reset",
          "/account/login");

  private final UserSessions sessions;
  private final RequiredActions actions;

  @Inject
  public RequiredActionsFilter(Materializer materializer, UserSessions sessions, RequiredActions actions) {
    super(materializer);
    this.sessions = sessions;
    this.actions = actions;
  }

  @Override
  public CompletionStage<Result> apply(
      Function<Http.RequestHeader, CompletionStage<Result>> next, Http.RequestHeader request) {
    String path = request.path();
    String destination = destination(path);
    if (destination == null || ALLOWED.stream().anyMatch(path::startsWith)) {
      return next.apply(request);
    }
    return sessions
        .current(request)
        .filter(state -> !actions.pending(state.user()).isEmpty())
        .<CompletionStage<Result>>map(
            state ->
                CompletableFuture.completedFuture(
                    Results.seeOther(
                        com.lattice.oidc.controllers.routes.RequiredActionsController.page(destination).url())))
        .orElseGet(() -> next.apply(request));
  }

  private static String destination(String path) {
    for (Map.Entry<String, String> gated : GATED.entrySet()) {
      if (path.equals(gated.getKey()) || path.startsWith(gated.getKey() + "/")) {
        return gated.getValue();
      }
    }
    return null;
  }
}

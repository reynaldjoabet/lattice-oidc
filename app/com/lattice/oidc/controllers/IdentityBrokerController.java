package com.lattice.oidc.controllers;

import com.lattice.oidc.common.Responses;
import com.lattice.oidc.handlers.IdentityProvider;
import com.lattice.oidc.handlers.IdentityProviders;
import com.lattice.oidc.models.AuthorizationInteraction;
import com.lattice.oidc.models.User;
import com.lattice.oidc.security.AuditService;
import com.lattice.oidc.security.Interactions;
import com.lattice.oidc.security.UserSessions;
import com.lattice.oidc.stores.UserStore;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import javax.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.mvc.Http;
import play.mvc.Result;

/**
 * Identity brokering: lets end-users sign in to Lattice with an existing account at an upstream
 * identity provider (Okta, Azure AD, Google, ...) during an authorization request. Lattice
 * delegates authentication to that provider, verifies the result, maps the external identity to a
 * local account ({@code <sub>@<provider-id>}) and starts a Lattice session. Keycloak's equivalent
 * is {@code IdentityBrokerService}.
 *
 * <ul>
 *   <li>{@code GET /api/federation/initiation/:id?ticket=...}: redirect to the provider.
 *   <li>{@code GET /api/federation/callback/:id}: the provider's redirect back to Lattice.
 * </ul>
 *
 * <p>The {@code /api/federation/...} paths are kept for compatibility with redirect URIs already
 * registered at the providers. Not to be confused with OpenID Federation 1.0 ({@link
 * FederationController}).
 */
public final class IdentityBrokerController extends BaseController {

  private static final Logger LOG = LoggerFactory.getLogger(IdentityBrokerController.class);
  private static final String KIND = "broker";
  private static final String AUTHZ = "authz";

  /** State of a sign-in with an upstream provider, keyed by the OAuth {@code state} value. */
  private record Pending(String providerId, String ticket, String verifier, String nonce) {}

  private final IdentityProviders providers;
  private final Interactions interactions;
  private final UserSessions sessions;
  private final UserStore users;

  @Inject
  public IdentityBrokerController(
      IdentityProviders providers, Interactions interactions, UserSessions sessions, UserStore users) {
    this.providers = providers;
    this.interactions = interactions;
    this.sessions = sessions;
    this.users = users;
  }

  /**
   * Starts sign-in with an upstream identity provider from the authorization page: redirects the browser
   * to the provider's authorization endpoint (authorization code flow with PKCE, state and nonce).
   * The pending authorization request is identified by its {@code ticket}.
   */
  public CompletionStage<Result> initiation(Http.Request request, String providerId, String ticket) {
    return async(
        () -> {
          Optional<IdentityProvider> provider = providers.get(providerId);
          if (provider.isEmpty()) {
            return Pages.message(request, 404, "Unknown provider", "No such identity provider.");
          }
          String browserId = sessions.existingBrowserId(request).orElse(null);
          if (interactions.get(AUTHZ, ticket, browserId, AuthorizationInteraction.class).isEmpty()) {
            return Pages.message(
                request, 400, "Request expired", "Please start again from the application.");
          }
          String state = UserSessions.randomId();
          String verifier = UserSessions.randomId() + UserSessions.randomId();
          String nonce = UserSessions.randomId();
          try {
            URI location = provider.get().authenticationRequest(state, verifier, nonce);
            interactions.put(KIND, state, browserId, new Pending(providerId, ticket, verifier, nonce));
            return Responses.location(location.toString());
          } catch (IOException e) {
            LOG.warn("Identity provider {} initiation failed: {}", providerId, e.getMessage());
            return Pages.message(
                request, 502, "Provider unavailable", "The identity provider could not be reached.");
          }
        });
  }

  /**
   * Redirection endpoint for the upstream identity provider. Completes the code flow, validates the ID
   * token and the UserInfo response, provisions/updates the local account ({@code sub@provider-id}),
   * logs the user in and shows the authorization page again so that the user can authorize the
   * client.
   */
  public CompletionStage<Result> callback(Http.Request request, String providerId) {
    return async(
        () -> {
          String browserId = sessions.existingBrowserId(request).orElse(null);
          String state = request.queryString("state").orElse(null);
          Optional<Pending> pending = interactions.take(KIND, state, browserId, Pending.class);
          Optional<IdentityProvider> provider = providers.get(providerId);
          if (pending.isEmpty()
              || provider.isEmpty()
              || !pending.get().providerId().equals(providerId)) {
            return Pages.message(
                request, 400, "Request expired", "Please start again from the application.");
          }
          Optional<AuthorizationInteraction> ix =
              interactions.get(AUTHZ, pending.get().ticket(), browserId, AuthorizationInteraction.class);
          if (ix.isEmpty()) {
            return Pages.message(
                request, 400, "Request expired", "Please start again from the application.");
          }

          UserInfo userInfo;
          try {
            userInfo =
                provider
                    .get()
                    .complete(
                        URI.create(requests.requestUrl(request)),
                        state,
                        pending.get().verifier(),
                        pending.get().nonce());
          } catch (IOException e) {
            LOG.warn("Identity provider {} login failed: {}", providerId, e.getMessage());
            audit.record(
                request, AuditService.Event.BROKERED_LOGIN_FAILED, "identity_provider", providerId);
            var page = ix.get().page().withError("Login with the external provider failed.");
            return Responses.of(
                502, views.html.oidc.authorization.render(page, request).body(), Responses.HTML, null);
          }

          User user = provision(providerId, userInfo);
          Map<String, String> sessionOut = new HashMap<>();
          sessions.login(user, System.currentTimeMillis() / 1000L, null, sessionOut);
          audit.record(
              request,
              AuditService.Event.BROKERED_LOGIN,
              "subject",
              user.getSubject(),
              "identity_provider",
              providerId);
          var page = ix.get().page().withLoggedInAs(Optional.of(user.displayName())).withError(null);
          interactions.put(
              AUTHZ,
              pending.get().ticket(),
              browserId,
              ix.get().withPage(page).withShownSubject(user.getSubject()));
          Result result =
              Responses.of(
                  200, views.html.oidc.authorization.render(page, request).body(), Responses.HTML, null);
          return sessions.apply(result, request, sessionOut);
        });
  }

  /** Creates/updates the local account mirroring the external user ({@code sub@provider-id}). */
  private User provision(String providerId, UserInfo info) {
    Map<String, Object> claims = new LinkedHashMap<>(info.toJSONObject());
    claims.remove("sub");
    User user =
        new User(info.getSubject().getValue() + "@" + providerId, null, null, claims, Map.of(), List.of());
    users.save(user);
    return user;
  }
}

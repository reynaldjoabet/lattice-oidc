package com.lattice.oidc.controllers;

import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.handlers.IdentityProvider;
import com.lattice.oidc.handlers.IdentityProviders;
import com.lattice.oidc.models.AccountLinkPage;
import com.lattice.oidc.models.AuthorizationInteraction;
import com.lattice.oidc.models.User;
import com.lattice.oidc.security.AuditService;
import com.lattice.oidc.security.Interactions;
import com.lattice.oidc.security.LoginService;
import com.lattice.oidc.security.UserSessions;
import com.lattice.oidc.stores.IdentityLinkStore;
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
 *   <li>{@code POST /api/federation/link}: the answer to "You already have an account": link the
 *       upstream identity to it (with that account's password) or keep a separate account.
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
  private static final String LINK = "broker-link";

  /** State of a sign-in with an upstream provider, keyed by the OAuth {@code state} value. */
  private record Pending(String providerId, String ticket, String verifier, String nonce) {}

  /**
   * A verified upstream sign-in whose email matches an existing password account, waiting for the
   * user to link the two or keep them separate. Keyed by a random id, bound to the browser.
   */
  private record PendingLink(
      String providerId,
      String providerName,
      String externalSubject,
      Map<String, Object> claims,
      String localSubject,
      String ticket) {}

  private final IdentityProviders providers;
  private final SignInFlow flow;
  private final Interactions interactions;
  private final UserSessions sessions;
  private final UserStore users;
  private final IdentityLinkStore links;
  private final LoginService login;

  @Inject
  public IdentityBrokerController(
      IdentityProviders providers,
      Interactions interactions,
      UserSessions sessions,
      UserStore users,
      IdentityLinkStore links,
      LoginService login,
      SignInFlow flow) {
    this.flow = flow;
    this.providers = providers;
    this.interactions = interactions;
    this.sessions = sessions;
    this.users = users;
    this.links = links;
    this.login = login;
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
   * Redirection endpoint for the upstream identity provider. Completes the code flow and validates
   * the ID token and the UserInfo response. Then:
   *
   * <ul>
   *   <li>an upstream identity already linked to a local account signs in to that account;
   *   <li>an email that matches an existing password account asks whether to link the two;
   *   <li>otherwise the local account {@code sub@provider-id} is created/updated and signed in.
   * </ul>
   *
   * <p>Signed in, the user sees the consent page for the pending authorization request.
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
          Optional<AuthorizationInteraction> interaction =
              interactions.get(AUTHZ, pending.get().ticket(), browserId, AuthorizationInteraction.class);
          if (interaction.isEmpty()) {
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
            var page =
                interaction.get().page().withLoggedInAs(Optional.empty()).withError("Login with the external provider failed.");
            return Pages.authorization(request, page, 502);
          }

          String externalSubject = userInfo.getSubject().getValue();
          Map<String, Object> claims = new LinkedHashMap<>(userInfo.toJSONObject());
          claims.remove("sub");
          String ticket = pending.get().ticket();

          // Already linked: sign in to the local account.
          Optional<User> linked = links.localSubject(providerId, externalSubject).flatMap(users::bySubject);
          if (linked.isPresent()) {
            return signIn(request, browserId, ticket, interaction.get(), linked.get(), providerId);
          }

          // The email belongs to an existing password account: offer to link them.
          Optional<User> existing =
              Optional.ofNullable(userInfo.getEmailAddress())
                  .flatMap(users::byEmail)
                  .filter(user -> user.passwordHash() != null);
          if (existing.isPresent()) {
            String linkId = UserSessions.randomId();
            PendingLink link =
                new PendingLink(
                    providerId, provider.get().name(), externalSubject, claims, existing.get().getSubject(), ticket);
            interactions.put(LINK, linkId, browserId, link);
            return linkPage(request, linkId, link, existing.get(), Optional.empty(), 200);
          }

          return signIn(request, browserId, ticket, interaction.get(), provision(providerId, externalSubject, claims), providerId);
        });
  }

  /**
   * The answer to "You already have an account". {@code link} with the existing account's password
   * links the upstream identity to it (the password check has the usual lockout); {@code separate}
   * creates the {@code sub@provider-id} account instead. Either way the user is signed in and sees
   * the consent page.
   */
  public CompletionStage<Result> link(Http.Request request) {
    return async(
        () -> {
          Map<String, String[]> form = Requests.form(request);
          String linkId = Requests.first(form, "linkId");
          String browserId = sessions.existingBrowserId(request).orElse(null);
          Optional<PendingLink> pending = interactions.get(LINK, linkId, browserId, PendingLink.class);
          Optional<AuthorizationInteraction> interaction =
              pending.flatMap(waiting -> interactions.get(AUTHZ, waiting.ticket(), browserId, AuthorizationInteraction.class));
          Optional<User> local = pending.flatMap(waiting -> users.bySubject(waiting.localSubject()));
          if (pending.isEmpty() || interaction.isEmpty() || local.isEmpty()) {
            return Pages.message(
                request, 400, "Request expired", "Please start again from the application.");
          }
          PendingLink link = pending.get();

          if (!form.containsKey("link")) {
            interactions.take(LINK, linkId, browserId, PendingLink.class);
            User separate = provision(link.providerId(), link.externalSubject(), link.claims());
            return signIn(request, browserId, link.ticket(), interaction.get(), separate, link.providerId());
          }

          LoginService.Result result = login.authenticate(local.get().loginId(), Requests.first(form, "password"), request.remoteAddress());
          auditLogin(request, local.get().loginId(), result);
          if (result.outcome() != LoginService.Outcome.SUCCESS) {
            return linkPage(
                request, linkId, link, local.get(), Optional.of(AuthorizationController.failureMessage(result)), 401);
          }
          interactions.take(LINK, linkId, browserId, PendingLink.class);
          if (flow.needsSecondFactor(local.get())) {
            // The account has an authenticator app: the link is made once the code is entered.
            return flow.challenge(
                request,
                local.get(),
                "Password",
                false,
                "authz:" + link.ticket(),
                Optional.of(new String[] {link.providerId(), link.externalSubject()}));
          }
          links.link(link.providerId(), link.externalSubject(), local.get().getSubject());
          audit.record(
              request,
              AuditService.Event.ACCOUNT_LINKED,
              "subject",
              local.get().getSubject(),
              "identity_provider",
              link.providerId());
          return signIn(request, browserId, link.ticket(), interaction.get(), local.get(), link.providerId());
        });
  }

  /** Starts a session for the user and shows the consent page of the pending request. */
  private Result signIn(
      Http.Request request,
      String browserId,
      String ticket,
      AuthorizationInteraction interaction,
      User user,
      String providerId) {
    Map<String, String> sessionOut = new HashMap<>();
    sessions.login(user, System.currentTimeMillis() / 1000L, null, sessionOut, request, providers.get(providerId).map(provider -> provider.name()).orElse(providerId));
    audit.record(
        request,
        AuditService.Event.BROKERED_LOGIN,
        "subject",
        user.getSubject(),
        "identity_provider",
        providerId);
    var page = interaction.page().withLoggedInAs(Optional.of(user.displayName())).withError(null);
    interactions.put(AUTHZ, ticket, browserId, interaction.withPage(page).withShownSubject(user.getSubject()));
    return sessions.apply(Pages.authorization(request, page, 200), request, sessionOut);
  }

  private static Result linkPage(
      Http.Request request,
      String linkId,
      PendingLink link,
      User local,
      Optional<String> error,
      int status) {
    Object email = link.claims().get("email");
    AccountLinkPage page =
        new AccountLinkPage(
            linkId,
            link.providerName(),
            email == null ? "" : email.toString(),
            local.displayName(),
            local.loginId(),
            error);
    return Responses.of(
        status, views.html.oidc.accountLink.render(page, request).body(), Responses.HTML, null);
  }

  /** Creates/updates the local account mirroring the external user ({@code sub@provider-id}). */
  private User provision(String providerId, String externalSubject, Map<String, Object> claims) {
    User user = new User(externalSubject + "@" + providerId, null, null, claims, Map.of(), List.of());
    users.save(user);
    return user;
  }
}

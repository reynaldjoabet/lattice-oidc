package com.lattice.oidc.controllers;

import com.authlete.common.dto.Client;
import com.authlete.common.dto.ClientAuthorizationGetListRequest;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.handlers.CibaHandler;
import com.lattice.oidc.handlers.IdentityProviders;
import com.lattice.oidc.models.AccountPage;
import com.lattice.oidc.models.User;
import com.lattice.oidc.security.AuditService;
import com.lattice.oidc.security.LoginService;
import com.lattice.oidc.security.SignInAlerts;
import com.lattice.oidc.security.UserSessions;
import com.lattice.oidc.security.UserSessions.LoginState;
import com.lattice.oidc.stores.IdentityLinkStore;
import com.lattice.oidc.stores.PasskeyStore;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import javax.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;

/**
 * The end-user's account page and the sign-in page for pages outside an authorization request.
 *
 * <ul>
 *   <li>{@code GET /account}: profile, sign-in alerts, apps with access, passkeys, sign-in methods,
 *       active sessions and waiting CIBA requests.
 *   <li>{@code POST /account/login}: sign in, then go to the account page, the CIBA approval page
 *       or the operator console ({@code next}, one of a fixed set: no open redirects).
 *   <li>{@code POST /account/apps/:clientId/remove}: remove an app's access (Authlete client
 *       authorization), which revokes its tokens.
 * </ul>
 */
public final class AccountController extends BaseController {

  private static final Logger LOG = LoggerFactory.getLogger(AccountController.class);

  /** Where {@code POST /account/login} may continue to, by name. */
  static final Map<String, String> DESTINATIONS =
      Map.of(
          "account", "/account",
          "ciba", "/ciba",
          "admin", "/admin",
          "device", "/api/device/verification",
          "offer", "/api/offer/issue");

  private final UserSessions sessions;
  private final SignInFlow flow;
  private final LoginService login;
  private final IdentityLinkStore links;
  private final IdentityProviders providers;
  private final CibaHandler ciba;
  private final LatticeConfig config;
  private final PasskeyStore passkeys;
  private final SignInAlerts alerts;
  private final com.lattice.oidc.security.SecondFactors secondFactors;

  @Inject
  public AccountController(
      UserSessions sessions,
      LoginService login,
      IdentityLinkStore links,
      IdentityProviders providers,
      CibaHandler ciba,
      LatticeConfig config,
      PasskeyStore passkeys,
      SignInAlerts alerts,
      SignInFlow flow,
      com.lattice.oidc.security.SecondFactors secondFactors) {
    this.secondFactors = secondFactors;
    this.flow = flow;
    this.sessions = sessions;
    this.login = login;
    this.links = links;
    this.providers = providers;
    this.ciba = ciba;
    this.config = config;
    this.passkeys = passkeys;
    this.alerts = alerts;
  }

  public CompletionStage<Result> index(Http.Request request) {
    return async(
        () -> {
          Optional<LoginState> current = sessions.current(request);
          if (current.isEmpty()) {
            return loginPage(request, "account", Optional.empty(), 200);
          }
          User user = current.get().user();
          List<AccountPage.App> apps = new ArrayList<>();
          boolean appsUnavailable = false;
          try {
            Client[] clients =
                api().getClientAuthorizationList(new ClientAuthorizationGetListRequest(user.getSubject())).getClients();
            if (clients != null) {
              for (Client client : clients) {
                apps.add(
                    new AccountPage.App(
                        client.getClientId(),
                        client.getClientName() != null ? client.getClientName() : String.valueOf(client.getClientId()),
                        Optional.ofNullable(client.getLogoUri()).map(Object::toString),
                        Optional.ofNullable(client.getClientUri()).map(Object::toString)));
              }
            }
          } catch (RuntimeException e) {
            LOG.warn("Could not list the apps authorized by {}: {}", user.getSubject(), e.getMessage());
            appsUnavailable = true;
          }
          Object email = user.getClaim("email", null);
          AccountPage page =
              new AccountPage(
                  user.displayName(),
                  Optional.ofNullable(email).map(Object::toString),
                  apps,
                  appsUnavailable,
                  signInMethods(user),
                  config.ciba().mode() == LatticeConfig.CibaMode.BUILTIN ? ciba.pendingFor(user.getSubject()).size() : 0,
                  AdminController.isAdmin(user, config),
                  passkeys.forSubject(user.getSubject()),
                  sessions.sessionsOf(user.getSubject()).size(),
                  alerts.pending(user.getSubject(), current.get().sessionId()),
                  new AccountPage.TwoStep(
                      secondFactors.enrolled(user.getSubject()),
                      secondFactors.remainingRecoveryCodes(user.getSubject()),
                      user.passwordHash() != null));
          return Responses.of(200, views.html.oidc.account.render(page, request).body(), Responses.HTML, null);
        });
  }

  public CompletionStage<Result> login(Http.Request request) {
    return async(
        () -> {
          Map<String, String[]> form = Requests.form(request);
          String next = DESTINATIONS.containsKey(Requests.first(form, "next")) ? Requests.first(form, "next") : "account";
          String loginId = Requests.first(form, "loginId");
          LoginService.Result result = login.authenticate(loginId, Requests.first(form, "password"), request.remoteAddress());
          auditLogin(request, loginId, result);
          if (result.outcome() != LoginService.Outcome.SUCCESS) {
            return loginPage(request, next, Optional.of(AuthorizationController.failureMessage(result)), 401);
          }
          boolean rememberMe = form.containsKey("rememberMe");
          if (flow.needsSecondFactor(result.user().get())) {
            return flow.challenge(request, result.user().get(), "Password", rememberMe, next, Optional.empty());
          }
          return flow.startAndRedirect(request, result.user().get(), "Password", null, rememberMe, next);
        });
  }

  public CompletionStage<Result> removeApp(Http.Request request, Long clientId) {
    return async(
        () -> {
          Optional<LoginState> current = sessions.current(request);
          if (current.isEmpty()) {
            return Pages.message(request, 400, "Session expired", "Please sign in again.");
          }
          String subject = current.get().user().getSubject();
          api().deleteClientAuthorization(clientId, subject);
          audit.record(request, AuditService.Event.APP_ACCESS_REMOVED, "subject", subject, "client_id", clientId);
          return Results.seeOther(DESTINATIONS.get("account"));
        });
  }

  private List<AccountPage.SignInMethod> signInMethods(User user) {
    List<AccountPage.SignInMethod> methods = new ArrayList<>();
    if (user.passwordHash() != null) {
      methods.add(new AccountPage.SignInMethod("Password", "login ID " + user.loginId()));
    } else if (com.lattice.oidc.security.LdapDirectory.isFederated(user)) {
      // From the LDAP directory: the password is checked, and changed, there.
      methods.add(new AccountPage.SignInMethod("Organisation password", "login ID " + user.loginId() + ", managed by your organisation's directory"));
    } else if (user.getSubject().contains("@")) {
      // A brokered account ({@code sub@provider-id}) signs in only through its provider.
      String providerId = user.getSubject().substring(user.getSubject().lastIndexOf('@') + 1);
      methods.add(new AccountPage.SignInMethod(providerName(providerId), "Used to create this account"));
    }
    for (IdentityLinkStore.Link link : links.linksOf(user.getSubject())) {
      methods.add(new AccountPage.SignInMethod(providerName(link.providerId()), "Linked"));
    }
    return methods;
  }

  private String providerName(String providerId) {
    return providers.get(providerId).map(provider -> provider.name()).orElse(providerId);
  }

  /** The sign-in page for {@code next} ("account", "ciba" or "admin"). */
  static Result loginPage(Http.Request request, String next, Optional<String> error, int status) {
    String purpose =
        switch (next) {
          case "ciba" -> "to review sign-in requests";
          case "admin" -> "to open the operator console";
          default -> "to manage your account";
        };
    return Responses.of(
        status, views.html.oidc.login.render(next, purpose, error, request).body(), Responses.HTML, null);
  }
}

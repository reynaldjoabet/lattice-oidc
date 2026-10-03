package com.lattice.oidc.controllers;

import com.authlete.common.dto.AuthorizationFailRequest.Reason;
import com.authlete.common.dto.AuthorizationRequest;
import com.authlete.common.dto.AuthorizationResponse;
import com.authlete.common.types.Prompt;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.handlers.AuthorizationHandler;
import com.lattice.oidc.handlers.IdentityProviders;
import com.lattice.oidc.models.AuthorizationInteraction;
import com.lattice.oidc.models.AuthorizationPage;
import com.lattice.oidc.security.AuditService;
import com.lattice.oidc.security.Interactions;
import com.lattice.oidc.security.LoginService;
import com.lattice.oidc.security.UserSessions.LoginState;
import com.lattice.oidc.security.UserSessions;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import javax.inject.Inject;
import play.mvc.Http;
import play.mvc.Result;

/**
 * An implementation of the OAuth 2.0 authorization endpoint with OpenID Connect support, and of
 * the endpoint that receives the end-user's decision from the authorization (consent) page.
 *
 * <ul>
 *   <li>{@code GET|POST /api/authorization}
 *   <li>{@code POST /api/authorization/decision}
 * </ul>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1">RFC 6749, 3.1. Authorization Endpoint</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint">OpenID Connect Core 1.0, 3.1.2. Authorization Endpoint (Authorization Code Flow)</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthorizationEndpoint">OpenID Connect Core 1.0, 3.2.2. Authorization Endpoint (Implicit Flow)</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#HybridAuthorizationEndpoint">OpenID Connect Core 1.0, 3.3.2. Authorization Endpoint (Hybrid Flow)</a>
 */
public final class AuthorizationController extends BaseController {

  static final String KIND = "authz";

  private final UserSessions sessions;
  private final Interactions interactions;
  private final LoginService login;
  private final AuthorizationHandler service;
  private final IdentityProviders identityProviders;

  @Inject
  public AuthorizationController(
      UserSessions sessions,
      Interactions interactions,
      LoginService login,
      AuthorizationHandler service,
      IdentityProviders identityProviders) {
    this.sessions = sessions;
    this.interactions = interactions;
    this.login = login;
    this.service = service;
    this.identityProviders = identityProviders;
  }

  /**
   * The authorization endpoint for the {@code GET} method.
   *
   * <p>RFC 6749, 3.1 Authorization Endpoint says that the authorization endpoint MUST support the
   * {@code GET} method. The query string is passed to Authlete exactly as received.
   *
   * @see <a href="https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1">RFC 6749, 3.1 Authorization Endpoint</a>
   */
  public CompletionStage<Result> get(Http.Request request) {
    return async(() -> authorize(request, Requests.rawQuery(request)));
  }

  /**
   * The authorization endpoint for the {@code POST} method.
   *
   * <p>RFC 6749, 3.1 Authorization Endpoint says that the authorization endpoint MAY support the
   * {@code POST} method. In addition, OpenID Connect Core 1.0, 3.1.2.1. Authentication Request says
   * that the authorization endpoint MUST support the {@code POST} method.
   */
  public CompletionStage<Result> post(Http.Request request) {
    return async(() -> authorize(request, Requests.encode(Requests.form(request))));
  }

  /**
   * Handle the authorization request.
   */
  private Result authorize(Http.Request request, String parameters) {
    // Call Authlete's /api/auth/authorization API.
    AuthorizationResponse response =
        api().authorization(new AuthorizationRequest().setParameters(parameters));
    // The content of the response to the client application.
    // The format of the content varies depending on the action.
    String content = response.getResponseContent();
    // 'action' in the response denotes the next action which
    // this service implementation should take. Dispatch according to the action.
    return switch (response.getAction()) {
      // Process the authorization request with user interaction.
      case INTERACTION -> interaction(request, response);
      // Process the authorization request without user interaction.
      // The flow reaches here only when the authorization request
      // contained prompt=none.
      case NO_INTERACTION -> noInteraction(request, response);
      // 302 Found
      case LOCATION -> Responses.location(content);
      // 200 OK (response_mode=form_post)
      case FORM -> Responses.form(content);
      // 400 Bad Request
      case BAD_REQUEST -> Responses.badRequest(content);
      // 500 Internal Server Error
      case INTERNAL_SERVER_ERROR -> Responses.serverError(content);
      // This never happens.
      default -> throw unknownAction("/auth/authorization", response.getAction());
    };
  }

  /**
   * Shows the authorization page that asks the end-user to log in (if necessary) and to grant
   * authorization to the client application.
   *
   * <p>The state needed to process the decision is stored server-side, keyed by Authlete's ticket
   * and bound to this browser. The current login session is offered only when the request allows
   * reusing it (see {@link #reusableSession}).
   */
  private Result interaction(Http.Request request, AuthorizationResponse info) {
    Optional<LoginState> current = reusableSession(request, info);
    Optional<String> shown = current.map(s -> s.user().displayName());
    AuthorizationPage page = AuthorizationPage.from(info, shown, identityProviders.links());
    String bid = sessions.bid(request);
    interactions.put(
        KIND,
        info.getTicket(),
        bid,
        AuthorizationInteraction.from(
            info, page, current.map(s -> s.user().getSubject()).orElse(null)));
    return sessions.withBid(
        Responses.of(200, views.html.oidc.authorization.render(page, request).body(), Responses.HTML, null),
        request,
        bid);
  }

  /**
   * The current login session if the authorization request permits reusing it: not when
   * {@code prompt=login} is included, not when the authentication is older than {@code max_age}, and
   * not when a specific subject is requested and the logged-in user is someone else.
   */
  private Optional<LoginState> reusableSession(Http.Request request, AuthorizationResponse info) {
    Optional<LoginState> current = sessions.current(request);
    if (current.isEmpty()) {
      return current;
    }
    Prompt[] prompts = info.getPrompts();
    // prompt=login forces re-authentication.
    if (prompts != null && Arrays.asList(prompts).contains(Prompt.LOGIN)) {
      return Optional.empty();
    }
    // The maximum authentication age has elapsed.
    if (info.getMaxAge() > 0
        && System.currentTimeMillis() / 1000L - current.get().authTime() > info.getMaxAge()) {
      return Optional.empty();
    }
    // The current user is different from the requested subject.
    if (info.getSubject() != null && !info.getSubject().equals(current.get().user().getSubject())) {
      return Optional.empty();
    }
    return current;
  }

  /**
   * Processes an authorization request that contained {@code prompt=none}: the response must be
   * issued from the existing login session without showing any page, or the request must fail with
   * the precise reason ({@code login_required} etc.).
   *
   * <p>When prompt=none is contained in an authorization request, response.getClaims() returns null.
   * This means that user claims don't have to be collected. In other words, if an authorization
   * request contains prompt=none and requests user claims at the same time, Authlete regards such a
   * request as illegal, because Authlete does not provide any means to pre-configure consent for
   * claims. See the description about prompt=none in "OpenID Connect Core 1.0, 3.1.2.1.
   * Authentication Request" for details.
   */
  private Result noInteraction(Http.Request request, AuthorizationResponse info) {
    // Check 1. End-User Authentication
    // A user must have logged in.
    Optional<LoginState> current = sessions.current(request);
    if (current.isEmpty()) {
      return service.fail(info.getTicket(), Reason.NOT_LOGGED_IN);
    }
    LoginState state = current.get();
    // Check 2. Max Age
    // If a maximum authentication age is requested and it has elapsed, fail.
    if (info.getMaxAge() > 0
        && System.currentTimeMillis() / 1000L - state.authTime() > info.getMaxAge()) {
      return service.fail(info.getTicket(), Reason.EXCEEDS_MAX_AGE);
    }
    // Check 3. Subject and Check 4. ACR are performed by AuthorizationHandler.issue(): the
    // requested subject must match the current user, and an essential ACR must be satisfied.
    AuthorizationInteraction ix =
        AuthorizationInteraction.from(info, null, state.user().getSubject());
    // Issue
    return service.issue(
        ix, new AuthorizationHandler.Grant(state.user(), state.authTime(), state.sid()));
  }

  /**
   * Processes a request from the form in the authorization page.
   *
   * <p>This implementation uses {@code authorized}, {@code loginId} and {@code password} in the form
   * parameters. When the pair of login ID and password is wrong, the authorization page is displayed
   * again with an error message (the authorization request stays pending).
   *
   * @return A response to the user agent. Basically, the response will trigger redirection to the
   *     client's redirect endpoint.
   */
  public CompletionStage<Result> decision(Http.Request request) {
    return async(() -> decide(request));
  }

  private Result decide(Http.Request request) {
    Map<String, String[]> form = Requests.form(request);
    String ticket = Requests.first(form, "ticket");
    String bid = request.session().get("bid").orElse(null);
    Optional<AuthorizationInteraction> found =
        interactions.get(KIND, ticket, bid, AuthorizationInteraction.class);
    // The authorization request is unknown, expired, or was started in another browser.
    if (found.isEmpty()) {
      return Pages.message(
          request,
          400,
          "Request expired",
          "This authorization request is no longer valid. Please start again from the application.");
    }
    AuthorizationInteraction ix = found.get();

    // If the end-user did not grant authorization to the client application.
    // The end-user denied the authorization request.
    if (!form.containsKey("authorized")) {
      interactions.take(KIND, ticket, bid, AuthorizationInteraction.class);
      audit.record(request, AuditService.Event.CONSENT_DENIED, "client_id", ix.clientIdentifier());
      return service.fail(ticket, Reason.DENIED);
    }

    Map<String, String> sessionOut = new HashMap<>();
    AuthorizationHandler.Grant grant;
    // The subject (= unique identifier) of the end-user: either the one who logs in with this form,
    // or the one already logged in when the page was shown.
    String loginId = Requests.first(form, "loginId");
    if (loginId != null && !loginId.isBlank()) {
      LoginService.Result result = login.authenticate(loginId, Requests.first(form, "password"));
      auditLogin(request, loginId, result);
      if (result.outcome() != LoginService.Outcome.SUCCESS) {
        String message =
            result.outcome() == LoginService.Outcome.LOCKED
                ? "Too many failed attempts. Try again later."
                : "Invalid login ID or password.";
        return rerender(request, ix, message, 401);
      }
      long authTime = System.currentTimeMillis() / 1000L;
      String sid = sessions.login(result.user().get(), authTime, null, sessionOut);
      grant = new AuthorizationHandler.Grant(result.user().get(), authTime, sid);
    } else {
      Optional<LoginState> current = sessions.current(request);
      if (current.isEmpty()
          || ix.shownSubject() == null
          || !ix.shownSubject().equals(current.get().user().getSubject())) {
        // The end-user is not authenticated.
        return rerender(request, ix, "Please log in.", 401);
      }
      LoginState s = current.get();
      grant = new AuthorizationHandler.Grant(s.user(), s.authTime(), s.sid());
    }

    // Authorize the authorization request. The ticket is single-use, so the pending state is
    // removed first.
    interactions.take(KIND, ticket, bid, AuthorizationInteraction.class);
    audit.record(
        request,
        AuditService.Event.CONSENT_GRANTED,
        "subject",
        grant.user().getSubject(),
        "client_id",
        ix.clientIdentifier());
    return sessions.apply(service.issue(ix, grant), request, sessionOut);
  }

  /**
   * Displays the authorization page again, with a message (e.g. after a failed login).
   */
  private Result rerender(
      Http.Request request, AuthorizationInteraction ix, String message, int status) {
    AuthorizationPage page = ix.page().withError(message);
    return Responses.of(
        status, views.html.oidc.authorization.render(page, request).body(), Responses.HTML, null);
  }
}

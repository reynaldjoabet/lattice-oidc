package com.lattice.oidc.controllers;

import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.common.UserAgents;
import com.lattice.oidc.handlers.CibaHandler;
import com.lattice.oidc.models.AuthorizationInteraction;
import com.lattice.oidc.models.CibaApproval;
import com.lattice.oidc.models.Passkey;
import com.lattice.oidc.models.User;
import com.lattice.oidc.security.AuditService;
import com.lattice.oidc.security.Interactions;
import com.lattice.oidc.security.LoginService;
import com.lattice.oidc.security.Passkeys;
import com.lattice.oidc.security.UserSessions;
import com.lattice.oidc.security.UserSessions.LoginState;
import com.lattice.oidc.stores.PasskeyStore;
import com.lattice.oidc.stores.UserStore;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import java.util.regex.Pattern;
import javax.inject.Inject;
import play.mvc.BodyParser;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;

/**
 * Passkeys: the JSON endpoints behind {@code passkeys.js} and the passkey pages.
 *
 * <ul>
 *   <li>{@code POST /passkeys/registration/options}, {@code POST /passkeys/registration}: create a
 *       passkey for the signed-in user, then name it ({@code GET /passkeys/created}, {@code POST
 *       /passkeys/name}).
 *   <li>{@code POST /passkeys/assertion/options}, {@code POST /passkeys/assertion}: use a passkey
 *       to sign in ({@code signin}), raise the session's assurance ({@code stepup}), confirm a
 *       sensitive action ({@code reauth}) or approve a CIBA request ({@code approval}).
 *   <li>{@code GET /passkeys/failed}: the "didn't work" page.
 *   <li>{@code GET|POST /account/passkeys/:id/remove}: remove a passkey after confirming it's you.
 * </ul>
 *
 * Every ceremony is stored server-side under a random id bound to the browser, like other pending
 * flows, and continues only to a fixed set of destinations ({@code next}).
 */
public final class PasskeyController extends BaseController {

  private static final String KIND = "passkey";
  static final String REAUTH = "reauth";
  private static final String AUTHZ = AuthorizationController.KIND;
  /** How long a passkey or password confirmation allows sensitive account changes. */
  static final long REAUTH_SECONDS = 300;
  private static final Pattern TICKET = Pattern.compile("[A-Za-z0-9_.~-]{1,200}");

  /** A started ceremony, waiting for the browser's response. */
  private record Ceremony(
      String purpose,
      String next,
      String subject,
      String approvalId,
      String creationJson,
      String assertionJson) {

    static Ceremony registration(String next, String subject, PublicKeyCredentialCreationOptions options) {
      try {
        return new Ceremony("register", next, subject, null, options.toJson(), null);
      } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
        throw new IllegalStateException(e);
      }
    }

    static Ceremony assertion(String purpose, String next, String subject, String approvalId, AssertionRequest request) {
      try {
        return new Ceremony(purpose, next, subject, approvalId, null, request.toJson());
      } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
        throw new IllegalStateException(e);
      }
    }

    PublicKeyCredentialCreationOptions creation() {
      try {
        return PublicKeyCredentialCreationOptions.fromJson(creationJson);
      } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
        throw new IllegalStateException(e);
      }
    }

    AssertionRequest assertion() {
      try {
        return assertionJson == null ? null : AssertionRequest.fromJson(assertionJson);
      } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
        throw new IllegalStateException(e);
      }
    }
  }

  private final UserSessions sessions;
  private final Interactions interactions;
  private final Passkeys passkeys;
  private final PasskeyStore store;
  private final UserStore users;
  private final LoginService login;
  private final CibaHandler ciba;
  private final SignInFlow flow;

  @Inject
  public PasskeyController(
      UserSessions sessions,
      Interactions interactions,
      Passkeys passkeys,
      PasskeyStore store,
      UserStore users,
      LoginService login,
      CibaHandler ciba,
      SignInFlow flow) {
    this.flow = flow;
    this.sessions = sessions;
    this.interactions = interactions;
    this.passkeys = passkeys;
    this.store = store;
    this.users = users;
    this.login = login;
    this.ciba = ciba;
  }

  // ---------------------------------------------------------------- destinations

  /** "account", "ciba", "admin" or "authz:<ticket>"; anything else is "account". */
  public static String safeNext(String next) {
    if (next == null) {
      return "account";
    }
    if (next.startsWith("authz:") && TICKET.matcher(next.substring(6)).matches()) {
      return next;
    }
    return AccountController.DESTINATIONS.containsKey(next) ? next : "account";
  }

  public static String url(String next) {
    String safe = safeNext(next);
    if (safe.startsWith("authz:")) {
      return com.lattice.oidc.controllers.routes.AuthorizationController.continueAuthorization(safe.substring(6)).url();
    }
    return AccountController.DESTINATIONS.get(safe);
  }

  private static String failedUrl(String next) {
    return com.lattice.oidc.controllers.routes.PasskeyController.failed(safeNext(next)).url();
  }

  // ---------------------------------------------------------------- registration

  @BodyParser.Of(BodyParser.Json.class)
  public Result registrationOptions(Http.Request request) {
    Optional<LoginState> current = sessions.current(request);
    if (current.isEmpty()) {
      return error(401, "Sign in first.", "account");
    }
    String next = safeNext(text(request, "next"));
    PublicKeyCredentialCreationOptions options = passkeys.startRegistration(current.get().user());
    String id = UserSessions.randomId();
    String browserId = sessions.browserId(request);
    interactions.put(KIND, id, browserId, Ceremony.registration(next, current.get().user().getSubject(), options));
    return sessions.withBrowserId(
        json(Map.of("ceremony", id, "options", Jsons.readMap(toJson(options)))), request, browserId);
  }

  @BodyParser.Of(BodyParser.Json.class)
  public CompletionStage<Result> register(Http.Request request) {
    String id = text(request, "ceremony");
    String credential = credential(request);
    return async(
        () -> {
          Optional<LoginState> current = sessions.current(request);
          Optional<Ceremony> ceremony = take(request, id);
          if (current.isEmpty()
              || ceremony.isEmpty()
              || !"register".equals(ceremony.get().purpose())
              || !ceremony.get().subject().equals(current.get().user().getSubject())) {
            return error(400, "This request has expired.", ceremony.map(Ceremony::next).orElse("account"));
          }
          String defaultName = UserAgents.describe(request.header("User-Agent").orElse(null));
          try {
            Passkey passkey =
                passkeys.finishRegistration(current.get().user(), ceremony.get().creation(), credential, defaultName);
            audit.record(request, AuditService.Event.PASSKEY_ADDED, "subject", passkey.subject());
            return json(
                Map.of(
                    "redirect",
                    com.lattice.oidc.controllers.routes.PasskeyController.created(passkey.id(), ceremony.get().next()).url()));
          } catch (Passkeys.PasskeyException e) {
            return error(400, e.getMessage(), ceremony.get().next());
          }
        });
  }

  /** "Passkey created": name it, then continue. */
  public Result created(Http.Request request, String id, String next) {
    Optional<LoginState> current = sessions.current(request);
    Optional<Passkey> passkey = store.byId(id).filter(found -> current.isPresent() && found.subject().equals(current.get().user().getSubject()));
    if (passkey.isEmpty()) {
      return Results.seeOther(url(next));
    }
    return Responses.of(
        200, views.html.oidc.passkeyCreated.render(passkey.get(), safeNext(next), request).body(), Responses.HTML, null);
  }

  public Result name(Http.Request request) {
    Map<String, String[]> form = Requests.form(request);
    String next = safeNext(Requests.first(form, "next"));
    Optional<LoginState> current = sessions.current(request);
    String name = Optional.ofNullable(Requests.first(form, "name")).map(String::trim).orElse("");
    current.flatMap(state -> store.byId(Requests.first(form, "id")).filter(found -> found.subject().equals(state.user().getSubject())))
        .filter(found -> !name.isEmpty())
        .ifPresent(found -> store.save(found.withName(name.length() > 60 ? name.substring(0, 60) : name)));
    return Results.seeOther(url(next));
  }

  // ---------------------------------------------------------------- sign-in, step-up, re-authentication, approval

  @BodyParser.Of(BodyParser.Json.class)
  public Result assertionOptions(Http.Request request) {
    String purpose = Optional.ofNullable(text(request, "purpose")).orElse("signin");
    String next = safeNext(text(request, "next"));
    Optional<LoginState> current = sessions.current(request);
    AssertionRequest assertion;
    String subject = null;
    String approvalId = null;
    switch (purpose) {
      case "signin" -> assertion = passkeys.startSignIn();
      case "stepup", "reauth" -> {
        if (current.isEmpty()) {
          return error(401, "Sign in first.", next);
        }
        subject = current.get().user().getSubject();
        assertion = passkeys.startVerification(subject);
      }
      case "approval" -> {
        if (current.isEmpty()) {
          return error(401, "Sign in first.", "ciba");
        }
        subject = current.get().user().getSubject();
        approvalId = text(request, "approval");
        Optional<CibaApproval> approval = ciba.pendingFor(subject).stream().filter(found -> found.id().equals(text(request, "approval"))).findFirst();
        if (approval.isEmpty()) {
          return error(400, "This request is no longer waiting.", "ciba");
        }
        assertion = passkeys.startApproval(subject, approval.get().signedContent());
      }
      default -> {
        return error(400, "Unknown purpose.", next);
      }
    }
    String id = UserSessions.randomId();
    String browserId = sessions.browserId(request);
    interactions.put(KIND, id, browserId, Ceremony.assertion(purpose, next, subject, approvalId, assertion));
    return sessions.withBrowserId(
        json(Map.of("ceremony", id, "options", Jsons.readMap(toJson(assertion)))), request, browserId);
  }

  @BodyParser.Of(BodyParser.Json.class)
  public CompletionStage<Result> assertion(Http.Request request) {
    String id = text(request, "ceremony");
    String credential = credential(request);
    return async(
        () -> {
          Optional<Ceremony> ceremony = take(request, id);
          if (ceremony.isEmpty() || ceremony.get().assertion() == null) {
            return error(400, "This request has expired.", "account");
          }
          Ceremony started = ceremony.get();
          Passkeys.Verified verified;
          try {
            verified = passkeys.finishAssertion(started.assertion(), credential);
          } catch (Passkeys.PasskeyException e) {
            audit.record(request, AuditService.Event.LOGIN_FAILED, "method", "passkey");
            return error(400, e.getMessage(), started.next());
          }
          Optional<User> user = users.bySubject(verified.subject());
          if (user.isEmpty() || (started.subject() != null && !started.subject().equals(verified.subject()))) {
            return error(400, "This passkey belongs to another account.", started.next());
          }
          return switch (started.purpose()) {
            case "signin" -> signIn(request, user.get(), started.next());
            case "stepup" -> {
              audit.record(request, AuditService.Event.STEP_UP, "subject", verified.subject());
              yield sessions.stepUp(json(Map.of("ok", true)), request, passkeys.acr());
            }
            case "reauth" -> {
              Optional<LoginState> current = sessions.current(request);
              current.ifPresent(
                  state -> interactions.put(REAUTH, state.sessionId(), sessions.browserId(request), Instant.now()));
              yield json(Map.of("ok", true));
            }
            case "approval" -> {
              Optional<CibaApproval> decided =
                  ciba.decide(verified.subject(), started.approvalId(), true, Optional.of(passkeys.acr()));
              if (decided.isEmpty()) {
                yield error(400, "This request is no longer waiting.", "ciba");
              }
              audit.record(request, AuditService.Event.CIBA_APPROVED, "subject", verified.subject(), "client", decided.get().clientName(), "method", "passkey");
              yield json(Map.of("redirect", com.lattice.oidc.controllers.routes.CibaApprovalController.approved().url()));
            }
            default -> error(400, "Unknown purpose.", started.next());
          };
        });
  }

  /**
   * Passkey sign-in: a new session (acr = phishing-resistant), then any required actions, then
   * continue. A passkey is itself two factors, so no authenticator code is asked for.
   */
  private Result signIn(Http.Request request, User user, String next) {
    audit.record(request, AuditService.Event.LOGIN_SUCCEEDED, "subject", user.getSubject(), "method", "passkey");
    SignInFlow.Started started = flow.start(request, user, "Passkey", passkeys.acr(), false, next);
    return sessions.apply(json(Map.of("redirect", started.destination())), request, started.sessionOut());
  }

  public Result failed(Http.Request request, String next) {
    String safe = safeNext(next);
    return Responses.of(
        200, views.html.oidc.passkeyFailed.render(url(safe), safe, request).body(), Responses.HTML, null);
  }

  // ---------------------------------------------------------------- removal

  public Result removePage(Http.Request request, String id) {
    Optional<LoginState> current = sessions.current(request);
    if (current.isEmpty()) {
      return AccountController.loginPage(request, "account", Optional.empty(), 200);
    }
    Optional<Passkey> passkey = owned(current.get(), id);
    if (passkey.isEmpty()) {
      return Results.seeOther(url("account"));
    }
    return removeView(request, current.get(), passkey.get(), Optional.empty(), 200);
  }

  public CompletionStage<Result> remove(Http.Request request, String id) {
    return async(
        () -> {
          Optional<LoginState> current = sessions.current(request);
          if (current.isEmpty()) {
            return Pages.message(request, 400, "Session expired", "Please sign in again.");
          }
          Optional<Passkey> passkey = owned(current.get(), id);
          if (passkey.isEmpty()) {
            return Results.seeOther(url("account"));
          }
          User user = current.get().user();
          boolean confirmed = recentlyConfirmed(request, current.get());
          String password = Requests.first(Requests.form(request), "password");
          if (!confirmed && password != null && !password.isEmpty() && user.loginId() != null) {
            LoginService.Result check = login.authenticate(user.loginId(), password, request.remoteAddress());
            auditPasswordConfirmation(request, user.getSubject(), check);
            if (check.outcome() != LoginService.Outcome.SUCCESS) {
              return removeView(request, current.get(), passkey.get(), Optional.of(AuthorizationController.failureMessage(check)), 401);
            }
            confirmed = true;
          }
          if (!confirmed) {
            return removeView(request, current.get(), passkey.get(), Optional.of("Confirm it's you first."), 401);
          }
          store.delete(passkey.get().id());
          audit.record(request, AuditService.Event.PASSKEY_REMOVED, "subject", user.getSubject());
          return Results.seeOther(url("account"));
        });
  }

  private Result removeView(Http.Request request, LoginState state, Passkey passkey, Optional<String> error, int status) {
    boolean otherPasskeys = store.forSubject(state.user().getSubject()).stream().anyMatch(other -> !other.id().equals(passkey.id()));
    return Responses.of(
        status,
        views.html.oidc.passkeyRemove
            .render(passkey, state.user().passwordHash() != null, otherPasskeys, error, request)
            .body(),
        Responses.HTML,
        null);
  }

  private boolean recentlyConfirmed(Http.Request request, LoginState state) {
    return interactions
        .get(REAUTH, state.sessionId(), sessions.existingBrowserId(request).orElse(null), Instant.class)
        .map(at -> at.plusSeconds(REAUTH_SECONDS).isAfter(Instant.now()))
        .orElse(false);
  }

  private Optional<Passkey> owned(LoginState state, String id) {
    return store.byId(id).filter(passkey -> passkey.subject().equals(state.user().getSubject()));
  }

  // ---------------------------------------------------------------- helpers

  private Optional<Ceremony> take(Http.Request request, String id) {
    return interactions.take(KIND, id, sessions.existingBrowserId(request).orElse(null), Ceremony.class);
  }

  private static String text(Http.Request request, String field) {
    var json = request.body().asJson();
    if (json == null || !json.hasNonNull(field)) {
      return null;
    }
    return json.get(field).asText();
  }

  /** The browser's PublicKeyCredential, re-serialized as JSON for the WebAuthn library. */
  private static String credential(Http.Request request) {
    var json = request.body().asJson();
    return json == null || !json.has("credential") ? "{}" : json.get("credential").toString();
  }

  private static String toJson(PublicKeyCredentialCreationOptions options) {
    try {
      return options.toCredentialsCreateJson();
    } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
      throw new IllegalStateException(e);
    }
  }

  private static String toJson(AssertionRequest request) {
    try {
      return request.toCredentialsGetJson();
    } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
      throw new IllegalStateException(e);
    }
  }

  private static Result json(Map<String, Object> body) {
    return Responses.json(200, Jsons.write(body)).withHeader(CACHE_CONTROL, "no-store");
  }

  /** A JSON failure with where the "didn't work" page should send the user afterwards. */
  private static Result error(int status, String message, String next) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("error", message);
    body.put("redirect", failedUrl(next));
    return Responses.json(status, Jsons.write(body)).withHeader(CACHE_CONTROL, "no-store");
  }
}

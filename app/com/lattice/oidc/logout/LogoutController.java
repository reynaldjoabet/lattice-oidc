package com.lattice.oidc.logout;

import com.authlete.common.dto.BackchannelLogoutTokenRequest;
import com.authlete.common.dto.BackchannelLogoutTokenResponse;
import com.authlete.common.dto.Client;
import com.authlete.common.dto.NativeSsoLogoutRequest;
import com.lattice.oidc.authorization.Pages;
import com.lattice.oidc.config.LatticeConfig;
import com.lattice.oidc.http.AuthleteController;
import com.lattice.oidc.http.Jsons;
import com.lattice.oidc.http.Requests;
import com.lattice.oidc.http.Responses;
import com.lattice.oidc.session.UserSessions;
import com.lattice.oidc.session.UserSessions.LoginState;
import com.lattice.oidc.token.JwtVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import javax.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.libs.ws.WSClient;
import play.mvc.Http;
import play.mvc.Result;

/**
 * OpenID Connect RP-Initiated Logout 1.0 ({@code GET|POST /api/logout}) with Back-Channel Logout
 * 1.0 notifications. Without a valid {@code id_token_hint} for the current user the end-user is
 * asked to confirm, so third-party sites cannot silently log users out.
 */
public final class LogoutController extends AuthleteController {

  private static final Logger LOG = LoggerFactory.getLogger(LogoutController.class);

  /** Validated logout request parameters. */
  public record LogoutRequest(
      Optional<String> idTokenHint,
      Optional<String> clientId,
      Optional<String> postLogoutRedirectUri,
      Optional<String> state) {}

  private final UserSessions sessions;
  private final JwtVerifier jwts;
  private final WSClient ws;
  private final LatticeConfig config;

  @Inject
  public LogoutController(UserSessions sessions, JwtVerifier jwts, WSClient ws, LatticeConfig config) {
    this.sessions = sessions;
    this.jwts = jwts;
    this.ws = ws;
    this.config = config;
  }

  public CompletionStage<Result> get(Http.Request request) {
    Map<String, String[]> params = Requests.decode(Requests.rawQuery(request));
    return async(() -> process(request, params, false));
  }

  public CompletionStage<Result> post(Http.Request request) {
    Map<String, String[]> params = Requests.form(request);
    return async(() -> process(request, params, false));
  }

  /** POST /api/logout/confirm — the user confirmed on the logout page (CSRF-protected). */
  public CompletionStage<Result> confirm(Http.Request request) {
    Map<String, String[]> params = Requests.form(request);
    return async(() -> process(request, params, params.containsKey("confirm")));
  }

  private Result process(Http.Request request, Map<String, String[]> params, boolean confirmed) {
    Optional<String> hint = opt(params, "id_token_hint");
    Optional<String> clientId = opt(params, "client_id");
    Optional<String> redirect = opt(params, "post_logout_redirect_uri");
    Optional<String> state = opt(params, "state");

    // id_token_hint: an ID token previously issued by this server (it may have expired). It
    // identifies the end-user and the client (aud/azp).
    Optional<JWTClaimsSet> hintClaims = Optional.empty();
    if (hint.isPresent()) {
      try {
        hintClaims = Optional.of(jwts.verify(hint.get(), null, true));
      } catch (JwtVerifier.InvalidJwtException e) {
        return Pages.message(request, 400, "Logout failed", "The id_token_hint is invalid.");
      }
      Optional<String> aud = hintClaims.flatMap(LogoutController::audience);
      if (clientId.isPresent() && aud.isPresent() && !clientId.equals(aud)) {
        return Pages.message(request, 400, "Logout failed", "client_id does not match the id_token_hint.");
      }
      clientId = clientId.or(() -> aud);
    }

    // post_logout_redirect_uri must exactly match a URI registered for the client; otherwise the
    // end-user is not redirected (open redirector protection).
    if (redirect.isPresent()) {
      if (clientId.isEmpty() || !allowedRedirect(clientId.get(), redirect.get())) {
        return Pages.message(
            request, 400, "Logout failed", "post_logout_redirect_uri is not registered for the client.");
      }
    }

    // Without an id_token_hint identifying the current user (or its session), ask the end-user to
    // confirm, so that third-party sites cannot silently log users out.
    Optional<LoginState> current = sessions.current(request);
    if (current.isPresent() && !confirmed) {
      String subject = current.get().user().getSubject();
      boolean hintMatches =
          hintClaims.isPresent()
              && (subject.equals(hintClaims.get().getSubject())
                  || current.get().sid().equals(stringClaim(hintClaims.get(), "sid")));
      if (!hintMatches) {
        LogoutRequest pending = new LogoutRequest(hint, clientId, redirect, state);
        return Responses.of(
            200, views.html.oidc.logoutConfirm.render(pending, request).body(), Responses.HTML, null);
      }
    }

    Result result = done(request, redirect, state);
    if (current.isPresent()) {
      endSession(current.get());
      result = sessions.logout(result, request, current.get().sid());
    }
    return result;
  }

  private Result done(Http.Request request, Optional<String> redirect, Optional<String> state) {
    if (redirect.isPresent()) {
      String url = redirect.get();
      if (state.isPresent()) {
        url += (url.contains("?") ? "&" : "?") + "state=" + URLEncoder.encode(state.get(), StandardCharsets.UTF_8);
      }
      return Responses.location(url);
    }
    return Pages.message(request, 200, "Signed out", "You have been signed out.");
  }

  /** Back-channel logout to every client of the session, then end native SSO for it. */
  private void endSession(LoginState state) {
    String sid = state.sid();
    for (String client : sessions.clients(sid)) {
      try {
        BackchannelLogoutTokenResponse r =
            api()
                .backchannelLogoutToken(
                    new BackchannelLogoutTokenRequest()
                        .setClientIdentifier(client)
                        .setSubject(state.user().getSubject())
                        .setSessionId(sid),
                    null);
        if (r.getAction() == BackchannelLogoutTokenResponse.Action.OK
            && r.getBackchannelLogoutUri() != null
            && r.getLogoutToken() != null) {
          ws.url(r.getBackchannelLogoutUri().toString())
              .setFollowRedirects(false)
              .setRequestTimeout(config.backchannelLogoutTimeout())
              .setContentType("application/x-www-form-urlencoded")
              .post("logout_token=" + URLEncoder.encode(r.getLogoutToken(), StandardCharsets.UTF_8))
              .whenComplete(
                  (resp, err) -> {
                    if (err != null || resp.getStatus() / 100 != 2) {
                      LOG.warn(
                          "Back-channel logout to client {} failed: {}",
                          client,
                          err != null ? err.getMessage() : "HTTP " + resp.getStatus());
                    }
                  });
        }
      } catch (RuntimeException e) {
        LOG.warn("Back-channel logout token for client {} failed: {}", client, e.getMessage());
      }
    }
    try {
      api().nativeSsoLogout(new NativeSsoLogoutRequest().setSessionId(sid), null);
    } catch (RuntimeException e) {
      LOG.warn("Native SSO logout failed: {}", e.getMessage());
    }
  }

  /** Exact match against post_logout_redirect_uris (custom client metadata), else redirect_uris. */
  private boolean allowedRedirect(String clientId, String uri) {
    Client client;
    try {
      client = api().getClient(clientId);
    } catch (RuntimeException e) {
      return false;
    }
    if (client == null) {
      return false;
    }
    List<String> allowed = new ArrayList<>();
    if (client.getCustomMetadata() != null) {
      Object v = Jsons.readMap(client.getCustomMetadata()).get("post_logout_redirect_uris");
      if (v instanceof List<?> l) {
        l.forEach(o -> allowed.add(String.valueOf(o)));
      }
    }
    if (allowed.isEmpty() && client.getRedirectUris() != null) {
      allowed.addAll(Arrays.asList(client.getRedirectUris()));
    }
    return allowed.contains(uri);
  }

  private static Optional<String> audience(JWTClaimsSet claims) {
    String azp = stringClaim(claims, "azp");
    if (azp != null) {
      return Optional.of(azp);
    }
    List<String> aud = claims.getAudience();
    return aud != null && aud.size() == 1 ? Optional.of(aud.get(0)) : Optional.empty();
  }

  private static String stringClaim(JWTClaimsSet claims, String name) {
    Object v = claims.getClaim(name);
    return v instanceof String s ? s : null;
  }

  private static Optional<String> opt(Map<String, String[]> params, String name) {
    return Optional.ofNullable(Requests.first(params, name)).filter(v -> !v.isEmpty());
  }
}

package com.lattice.oidc.handlers;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.BackchannelLogoutTokenRequest;
import com.authlete.common.dto.BackchannelLogoutTokenResponse;
import com.authlete.common.dto.Client;
import com.authlete.common.dto.NativeSsoLogoutRequest;
import com.lattice.oidc.client.AuthleteExecutionContext;
import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.models.LogoutRequest;
import com.lattice.oidc.security.JwtVerifier;
import com.lattice.oidc.security.UserSessions.LoginState;
import com.lattice.oidc.security.UserSessions;
import com.nimbusds.jwt.JWTClaimsSet;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;
import org.apache.pekko.actor.ActorSystem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.libs.ws.WSClient;

/**
 * Protocol logic of OpenID Connect RP-Initiated Logout 1.0 and Back-Channel Logout 1.0: validates
 * logout requests and ends login sessions everywhere (clients and native SSO).
 */
@Singleton
public final class LogoutHandler {

  /** Thrown when the logout request is invalid; the message is safe to show to the end-user. */
  public static final class InvalidLogoutRequest extends Exception {
    private static final long serialVersionUID = 1L;

    InvalidLogoutRequest(String message) {
      super(message);
    }
  }

  private static final Logger LOG = LoggerFactory.getLogger(LogoutHandler.class);

  private final Provider<AuthleteApi> api;
  private final JwtVerifier jwts;
  private final UserSessions sessions;
  private final WSClient ws;
  private final LatticeConfig config;
  private final ActorSystem actorSystem;
  private final AuthleteExecutionContext executionContext;

  /** Waits before the second and third delivery attempts of a logout token. */
  static final List<Duration> RETRY_DELAYS = List.of(Duration.ofSeconds(5), Duration.ofSeconds(30));

  @Inject
  public LogoutHandler(
      Provider<AuthleteApi> api,
      JwtVerifier jwts,
      UserSessions sessions,
      WSClient ws,
      LatticeConfig config,
      ActorSystem actorSystem,
      AuthleteExecutionContext executionContext) {
    this.api = api;
    this.jwts = jwts;
    this.sessions = sessions;
    this.ws = ws;
    this.config = config;
    this.actorSystem = actorSystem;
    this.executionContext = executionContext;
  }

  /** Validates the logout request parameters. */
  public LogoutRequest validate(Map<String, String[]> params) throws InvalidLogoutRequest {
    Optional<String> hint = optionalParameter(params, "id_token_hint");
    Optional<String> clientId = optionalParameter(params, "client_id");
    Optional<String> redirect = optionalParameter(params, "post_logout_redirect_uri");
    Optional<String> state = optionalParameter(params, "state");

    // id_token_hint: an ID token previously issued by this server (it may have expired). It
    // identifies the end-user and the client (aud/azp).
    Optional<JWTClaimsSet> hintClaims = Optional.empty();
    if (hint.isPresent()) {
      try {
        hintClaims = Optional.of(jwts.verify(hint.get(), null, true));
      } catch (JwtVerifier.InvalidJwtException e) {
        throw new InvalidLogoutRequest("The id_token_hint is invalid.");
      }
      Optional<String> hintAudience = hintClaims.flatMap(LogoutHandler::audience);
      if (clientId.isPresent() && hintAudience.isPresent() && !clientId.equals(hintAudience)) {
        throw new InvalidLogoutRequest("client_id does not match the id_token_hint.");
      }
      clientId = clientId.or(() -> hintAudience);
    }

    // post_logout_redirect_uri must exactly match a URI registered for the client; otherwise the
    // end-user is not redirected (open redirector protection).
    if (redirect.isPresent()
        && (clientId.isEmpty() || !allowedRedirect(clientId.get(), redirect.get()))) {
      throw new InvalidLogoutRequest("post_logout_redirect_uri is not registered for the client.");
    }

    return new LogoutRequest(
        hint,
        clientId,
        redirect,
        state,
        hintClaims.map(JWTClaimsSet::getSubject),
        hintClaims.map(c -> stringClaim(c, "sid")));
  }

  /**
   * Whether the request's id_token_hint identifies the current user (or its session). Without
   * such a hint the end-user must confirm, so that third-party sites cannot silently log users
   * out.
   */
  public boolean hintMatches(LogoutRequest request, LoginState current) {
    return request.hintSubject().filter(current.user().getSubject()::equals).isPresent()
        || request.hintSessionId().filter(current.sessionId()::equals).isPresent();
  }

  /** The URL to redirect to after logout ({@code state} appended), if any. */
  public Optional<String> redirectUrl(LogoutRequest request) {
    return request
        .postLogoutRedirectUri()
        .map(
            url ->
                request
                    .state()
                    .map(
                        state ->
                            url
                                + (url.contains("?") ? "&" : "?")
                                + "state="
                                + URLEncoder.encode(state, StandardCharsets.UTF_8))
                    .orElse(url));
  }

  /**
   * Ends the login session everywhere: sends a back-channel logout token (generated by Authlete's
   * /backchannel/logout/token API) to every client that obtained tokens in the session, then ends
   * native SSO for it (/nativesso/logout). Notifications are sent asynchronously; a failed delivery
   * is retried twice ({@link #RETRY_DELAYS}), then logged. Failures are never shown to the end-user.
   * Retries are kept on this server, so a restart during them drops the remaining attempts.
   */
  public void endSession(LoginState state) {
    String sessionId = state.sessionId();
    for (String client : sessions.clients(sessionId)) {
      try {
        BackchannelLogoutTokenResponse r =
            api.get()
                .backchannelLogoutToken(
                    new BackchannelLogoutTokenRequest()
                        .setClientIdentifier(client)
                        .setSubject(state.user().getSubject())
                        .setSessionId(sessionId),
                    null);
        if (r.getAction() == BackchannelLogoutTokenResponse.Action.OK
            && r.getBackchannelLogoutUri() != null
            && r.getLogoutToken() != null) {
          deliver(client, r.getBackchannelLogoutUri().toString(), r.getLogoutToken(), 0);
        }
      } catch (RuntimeException e) {
        LOG.warn("Back-channel logout token for client {} failed: {}", client, e.getMessage());
      }
    }
    try {
      api.get().nativeSsoLogout(new NativeSsoLogoutRequest().setSessionId(sessionId), null);
    } catch (RuntimeException e) {
      LOG.warn("Native SSO logout failed: {}", e.getMessage());
    }
  }

  /** Posts a logout token to the client, retrying after {@link #RETRY_DELAYS} if it fails. */
  private void deliver(String client, String uri, String logoutToken, int attempt) {
    ws.url(uri)
        .setFollowRedirects(false)
        .setRequestTimeout(config.backchannelLogoutTimeout())
        .setContentType("application/x-www-form-urlencoded")
        .post("logout_token=" + URLEncoder.encode(logoutToken, StandardCharsets.UTF_8))
        .whenComplete(
            (response, error) -> {
              if (error == null && response.getStatus() / 100 == 2) {
                return;
              }
              String reason = error != null ? error.getMessage() : "HTTP " + response.getStatus();
              if (attempt < RETRY_DELAYS.size()) {
                LOG.info("Back-channel logout to client {} failed ({}); retrying", client, reason);
                actorSystem
                    .scheduler()
                    .scheduleOnce(
                        RETRY_DELAYS.get(attempt),
                        () -> deliver(client, uri, logoutToken, attempt + 1),
                        executionContext);
              } else {
                LOG.warn("Back-channel logout to client {} failed after {} attempts: {}", client, attempt + 1, reason);
              }
            });
  }

  /**
   * Ends every session of the account except {@code keepSessionId} (null ends them all), each with
   * back-channel logout to its apps.
   *
   * @return the client identifiers that were told to sign out
   */
  public java.util.Set<String> endSessionsOf(com.lattice.oidc.models.User user, String keepSessionId) {
    java.util.Set<String> clients = new java.util.TreeSet<>();
    for (UserSessions.SessionInfo session : sessions.sessionsOf(user.getSubject())) {
      if (session.sessionId().equals(keepSessionId)) {
        continue;
      }
      clients.addAll(session.clients());
      endSession(new LoginState(user, session.sessionId(), 0L, null));
      sessions.end(session.sessionId());
    }
    return clients;
  }

  /** Exact match against post_logout_redirect_uris (custom client metadata), else redirect_uris. */
  private boolean allowedRedirect(String clientId, String uri) {
    Client client;
    try {
      client = api.get().getClient(clientId);
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
    String authorizedParty = stringClaim(claims, "azp");
    if (authorizedParty != null) {
      return Optional.of(authorizedParty);
    }
    List<String> audiences = claims.getAudience();
    return audiences != null && audiences.size() == 1 ? Optional.of(audiences.get(0)) : Optional.empty();
  }

  private static String stringClaim(JWTClaimsSet claims, String name) {
    Object value = claims.getClaim(name);
    return value instanceof String string ? string : null;
  }

  private static Optional<String> optionalParameter(Map<String, String[]> params, String name) {
    return Optional.ofNullable(Requests.first(params, name)).filter(value -> !value.isEmpty());
  }
}

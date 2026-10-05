package com.lattice.oidc.security;

import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.common.UserAgents;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.SessionStore;
import com.lattice.oidc.stores.SessionStore.Session;
import com.lattice.oidc.stores.UserStore;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.inject.Inject;
import javax.inject.Singleton;
import play.mvc.Http;
import play.mvc.Result;

/**
 * Browser login sessions.
 *
 * <p>The signed Play session cookie carries only identifiers: {@code browser_id} (a stable browser
 * binding for pending interactions), {@code session_id} (the login session, rotated at every
 * login), {@code subject}, {@code auth_time} and {@code acr}. A session is valid only while its
 * {@code session_id} is registered server-side, so logout invalidates it even if the cookie is
 * replayed. The session ID is also the value of the {@code sid} claim in ID tokens and logout
 * tokens.
 *
 * <p>Each session also records how it was started (browser, IP, sign-in method) and when it was
 * last used, so users can see and end their sessions. A session lives at most {@code
 * lattice.session.max-lifespan} from sign-in, and ends earlier after {@code
 * lattice.session.idle-timeout} without activity. Sessions are kept in the {@link SessionStore}, so
 * every server sees the same ones.
 */
@Singleton
public final class UserSessions {

  public record LoginState(User user, String sessionId, long authTime, String acr) {}

  /** What the account page shows about a session. */
  public record SessionInfo(
      String sessionId,
      String device,
      String ip,
      String method,
      Instant createdAt,
      Instant lastSeenAt,
      Set<String> clients) {

    /** "Active now", "Last active 2 hours ago", ... */
    public String lastActive() {
      long minutes = Duration.between(lastSeenAt, Instant.now()).toMinutes();
      if (minutes < 5) {
        return "Active now";
      }
      if (minutes < 60) {
        return "Last active " + minutes + " minutes ago";
      }
      long hours = minutes / 60;
      if (hours < 24) {
        return "Last active " + hours + (hours == 1 ? " hour ago" : " hours ago");
      }
      long days = hours / 24;
      return "Last active " + days + (days == 1 ? " day ago" : " days ago");
    }
  }

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final String SESSION_ID = "session_id";
  /** Session key of the browser id (also in the values {@link #login} produces). */
  public static final String BROWSER_ID = "browser_id";
  private static final String SUBJECT = "subject";
  private static final String AUTH_TIME = "auth_time";
  private static final String ACR = "acr";
  private static final Duration TOUCH_INTERVAL = Duration.ofMinutes(1);

  private final SessionStore store;
  private final UserStore users;
  private final LatticeConfig config;
  private final SignInAlerts alerts;

  @Inject
  public UserSessions(SessionStore store, UserStore users, LatticeConfig config, SignInAlerts alerts) {
    this.store = store;
    this.users = users;
    this.config = config;
    this.alerts = alerts;
  }

  public static String randomId() {
    byte[] bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  /** The logged-in user, if the session is still registered, within its lifetime and not idle. */
  public Optional<LoginState> current(Http.RequestHeader request) {
    Http.Session session = request.session();
    Optional<String> sessionId = session.get(SESSION_ID);
    Optional<String> subject = session.get(SUBJECT);
    Optional<String> authTimeValue = session.get(AUTH_TIME);
    if (sessionId.isEmpty() || subject.isEmpty() || authTimeValue.isEmpty()) {
      return Optional.empty();
    }
    Optional<Session> record = live(sessionId.get());
    if (record.isEmpty() || !record.get().subject().equals(subject.get())) {
      return Optional.empty();
    }
    long authTime;
    try {
      authTime = Long.parseLong(authTimeValue.get());
    } catch (NumberFormatException e) {
      return Optional.empty();
    }
    store.touch(sessionId.get(), Instant.now(), TOUCH_INTERVAL);
    String acr = session.get(ACR).filter(value -> !value.isEmpty()).orElse(null);
    return users
        .bySubject(subject.get())
        .map(user -> new LoginState(user, sessionId.get(), authTime, acr));
  }

  /**
   * Whether a login session id is still active (used by native SSO). An app using the session
   * counts as activity.
   */
  public boolean isActive(String sessionId) {
    if (sessionId == null || live(sessionId).isEmpty()) {
      return false;
    }
    store.touch(sessionId, Instant.now(), TOUCH_INTERVAL);
    return true;
  }

  /** The session, if it exists, is within its maximum lifetime and hasn't been idle too long. */
  private Optional<Session> live(String sessionId) {
    Instant now = Instant.now();
    Optional<Session> found = store.find(sessionId);
    if (found.isPresent() && idle(found.get(), now)) {
      store.end(sessionId);
      return Optional.empty();
    }
    return found;
  }

  private boolean idle(Session session, Instant now) {
    Duration idleTimeout =
        session.rememberMe() ? config.rememberMe().idleTimeout() : config.sessionIdleTimeout();
    return !idleTimeout.isZero() && !session.lastSeenAt().plus(idleTimeout).isAfter(now);
  }

  /**
   * The browser's stable id, generating one if absent (persist it with {@link #withBrowserId}).
   * Used when a browser starts a multi-step flow.
   */
  public String browserId(Http.Request request) {
    return existingBrowserId(request).orElseGet(UserSessions::randomId);
  }

  /** The browser's id if it already has one (i.e. it has started a flow before). */
  public Optional<String> existingBrowserId(Http.Request request) {
    return request.session().get(BROWSER_ID);
  }

  public Result withBrowserId(Result result, Http.Request request, String browserId) {
    return result.addingToSession(request, BROWSER_ID, browserId);
  }

  /** Starts a new login session without request details (tests, internal callers). */
  public String login(User user, long authTime, String acr, Map<String, String> sessionOut) {
    return login(user, authTime, acr, sessionOut, null, "Password");
  }

  /**
   * Starts a new login session (new session ID, preventing session fixation) and returns its ID.
   * {@code method} describes how the user signed in ("Password", "Passkey", a provider name). A
   * sign-in from a browser the account has not used before raises a new sign-in alert.
   */
  public String login(
      User user,
      long authTime,
      String acr,
      Map<String, String> sessionOut,
      Http.RequestHeader request,
      String method) {
    return login(user, authTime, acr, sessionOut, request, method, false);
  }

  /**
   * As {@link #login(User, long, String, Map, Http.RequestHeader, String)}, where {@code rememberMe}
   * ("keep me signed in", if {@code lattice.session.remember-me.enabled}) gives the session the
   * longer limits of {@code lattice.session.remember-me}.
   */
  public String login(
      User user,
      long authTime,
      String acr,
      Map<String, String> sessionOut,
      Http.RequestHeader request,
      String method,
      boolean rememberMe) {
    boolean remembered = rememberMe && config.rememberMe().enabled();
    String sessionId = randomId();
    String browserId =
        request == null ? null : request.session().get(BROWSER_ID).orElseGet(UserSessions::randomId);
    String userAgent = request == null ? null : request.header("User-Agent").orElse(null);
    String ip = request == null ? null : request.remoteAddress();
    Instant now = Instant.now();
    store.create(
        new Session(
            sessionId,
            user.getSubject(),
            userAgent,
            ip,
            method,
            now,
            now,
            now.plus(remembered ? config.rememberMe().maxLifespan() : config.sessionMaxLifespan()),
            remembered));
    if (browserId != null) {
      sessionOut.put(BROWSER_ID, browserId);
      alerts.onSignIn(user.getSubject(), browserId, sessionId, UserAgents.describe(userAgent), ip, method);
    }
    sessionOut.put(SESSION_ID, sessionId);
    sessionOut.put(SUBJECT, user.getSubject());
    sessionOut.put(AUTH_TIME, Long.toString(authTime));
    sessionOut.put(ACR, acr == null ? "" : acr);
    return sessionId;
  }

  /** After step-up: the session now has a stronger authentication (new auth_time and acr). */
  public Result stepUp(Result result, Http.Request request, String acr) {
    return result.addingToSession(
        request, Map.of(ACR, acr, AUTH_TIME, Long.toString(System.currentTimeMillis() / 1000L)));
  }

  /** Applies session values produced by {@link #login} (and the browser binding) to a result. */
  public Result apply(Result result, Http.Request request, Map<String, String> values) {
    if (values.isEmpty()) {
      return result;
    }
    return result.addingToSession(request, values);
  }

  /** Records that a client obtained tokens in this session (for back-channel logout). */
  public void addClient(String sessionId, String clientIdentifier) {
    if (sessionId == null || clientIdentifier == null) {
      return;
    }
    store.addClient(sessionId, clientIdentifier);
  }

  public Set<String> clients(String sessionId) {
    return sessionId == null ? Set.of() : store.clients(sessionId);
  }

  /** The account's active sessions, most recently used first. */
  public List<SessionInfo> sessionsOf(String subject) {
    Instant now = Instant.now();
    return store.forSubject(subject).stream()
        .filter(session -> !idle(session, now))
        .map(
            session ->
                new SessionInfo(
                    session.id(),
                    UserAgents.describe(session.userAgent()),
                    session.ip(),
                    session.method(),
                    session.createdAt(),
                    session.lastSeenAt(),
                    store.clients(session.id())))
        .sorted(java.util.Comparator.comparing(SessionInfo::lastSeenAt).reversed())
        .toList();
  }

  /** The session, if it is still active and belongs to {@code subject}. */
  public Optional<SessionInfo> sessionOf(String subject, String sessionId) {
    return sessionsOf(subject).stream().filter(info -> info.sessionId().equals(sessionId)).findFirst();
  }

  /** Active sessions on every server (for the operator console). */
  public long countActive() {
    return store.countActive();
  }

  /** Ends a session server-side (its cookie stops working). Back-channel logout is the caller's. */
  public void end(String sessionId) {
    if (sessionId != null) {
      store.end(sessionId);
    }
  }

  /** Ends the login session server-side and strips it from the cookie (keeps the browser id). */
  public Result logout(Result result, Http.Request request, String sessionId) {
    end(sessionId);
    return result.removingFromSession(request, SESSION_ID, SUBJECT, AUTH_TIME, ACR);
  }
}

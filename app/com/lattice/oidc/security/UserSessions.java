package com.lattice.oidc.security;

import com.lattice.oidc.common.Caches;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.common.UserAgents;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.UserStore;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.inject.Inject;
import javax.inject.Singleton;
import play.cache.NamedCache;
import play.cache.SyncCacheApi;
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
 * last used, and sessions are indexed per account, so users can see and end them. A session lives
 * at most {@code lattice.session.max-lifespan} from sign-in; activity does not extend it.
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

  /** Server-side state of a login session; mutable fields are only the client set and last use. */
  private static final class SessionRecord {
    final String subject;
    final Set<String> clients = new LinkedHashSet<>();
    final String userAgent;
    final String ip;
    final String method;
    final Instant createdAt;
    volatile Instant lastSeenAt;

    SessionRecord(String subject, String userAgent, String ip, String method, Instant now) {
      this.subject = subject;
      this.userAgent = userAgent;
      this.ip = ip;
      this.method = method;
      this.createdAt = now;
      this.lastSeenAt = now;
    }
  }

  private final SyncCacheApi cache;
  private final UserStore users;
  private final LatticeConfig config;
  private final SignInAlerts alerts;

  @Inject
  public UserSessions(
      @NamedCache(Caches.SESSIONS) SyncCacheApi cache,
      UserStore users,
      LatticeConfig config,
      SignInAlerts alerts) {
    this.cache = cache;
    this.users = users;
    this.config = config;
    this.alerts = alerts;
  }

  public static String randomId() {
    byte[] bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  /** The logged-in user, if the session is still registered and within its maximum lifetime. */
  public Optional<LoginState> current(Http.Request request) {
    Http.Session session = request.session();
    Optional<String> sessionId = session.get(SESSION_ID);
    Optional<String> subject = session.get(SUBJECT);
    Optional<String> authTimeValue = session.get(AUTH_TIME);
    if (sessionId.isEmpty() || subject.isEmpty() || authTimeValue.isEmpty()) {
      return Optional.empty();
    }
    Optional<SessionRecord> record = cache.get(key(sessionId.get()));
    if (record.isEmpty() || !record.get().subject.equals(subject.get())) {
      return Optional.empty();
    }
    long authTime;
    try {
      authTime = Long.parseLong(authTimeValue.get());
    } catch (NumberFormatException e) {
      return Optional.empty();
    }
    Instant now = Instant.now();
    if (record.get().lastSeenAt.plus(TOUCH_INTERVAL).isBefore(now)) {
      record.get().lastSeenAt = now;
    }
    String acr = session.get(ACR).filter(value -> !value.isEmpty()).orElse(null);
    return users
        .bySubject(subject.get())
        .map(user -> new LoginState(user, sessionId.get(), authTime, acr));
  }

  /** Whether a login session id is still active (used by native SSO). */
  public boolean isActive(String sessionId) {
    return sessionId != null && cache.get(key(sessionId)).isPresent();
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
    String sessionId = randomId();
    String browserId =
        request == null ? null : request.session().get(BROWSER_ID).orElseGet(UserSessions::randomId);
    String userAgent = request == null ? null : request.header("User-Agent").orElse(null);
    String ip = request == null ? null : request.remoteAddress();
    SessionRecord record = new SessionRecord(user.getSubject(), userAgent, ip, method, Instant.now());
    cache.set(key(sessionId), record, (int) config.sessionMaxLifespan().toSeconds());
    synchronized (this) {
      Set<String> ids =
          cache.<Set<String>>get(indexKey(user.getSubject())).orElseGet(ConcurrentHashMap::newKeySet);
      ids.add(sessionId);
      cache.set(indexKey(user.getSubject()), ids, (int) config.sessionMaxLifespan().toSeconds());
    }
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
    cache.<SessionRecord>get(key(sessionId))
        .ifPresent(
            record -> {
              synchronized (record.clients) {
                record.clients.add(clientIdentifier);
              }
            });
  }

  public Set<String> clients(String sessionId) {
    return cache.<SessionRecord>get(key(sessionId))
        .map(
            record -> {
              synchronized (record.clients) {
                return Set.copyOf(record.clients);
              }
            })
        .orElse(Set.of());
  }

  /** The account's active sessions, most recently used first. */
  public List<SessionInfo> sessionsOf(String subject) {
    Set<String> ids = cache.<Set<String>>get(indexKey(subject)).orElse(Set.of());
    List<SessionInfo> sessions = new ArrayList<>();
    for (String id : List.copyOf(ids)) {
      Optional<SessionRecord> record = cache.get(key(id));
      if (record.isEmpty()) {
        ids.remove(id);
        continue;
      }
      SessionRecord found = record.get();
      sessions.add(
          new SessionInfo(
              id,
              UserAgents.describe(found.userAgent),
              found.ip,
              found.method,
              found.createdAt,
              found.lastSeenAt,
              clients(id)));
    }
    sessions.sort(Comparator.comparing(SessionInfo::lastSeenAt).reversed());
    return sessions;
  }

  /** The session, if it is still active and belongs to {@code subject}. */
  public Optional<SessionInfo> sessionOf(String subject, String sessionId) {
    return sessionsOf(subject).stream().filter(info -> info.sessionId().equals(sessionId)).findFirst();
  }

  /** Ends a session server-side (its cookie stops working). Back-channel logout is the caller's. */
  public void end(String sessionId) {
    if (sessionId == null) {
      return;
    }
    Optional<SessionRecord> record = cache.get(key(sessionId));
    cache.remove(key(sessionId));
    record
        .flatMap(found -> cache.<Set<String>>get(indexKey(found.subject)))
        .ifPresent(ids -> ids.remove(sessionId));
  }

  /** Ends the login session server-side and strips it from the cookie (keeps the browser id). */
  public Result logout(Result result, Http.Request request, String sessionId) {
    end(sessionId);
    return result.removingFromSession(request, SESSION_ID, SUBJECT, AUTH_TIME, ACR);
  }

  private static String key(String sessionId) {
    return "session:" + sessionId;
  }

  private static String indexKey(String subject) {
    return "user-sessions:" + subject;
  }
}

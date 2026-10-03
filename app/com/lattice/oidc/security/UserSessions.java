package com.lattice.oidc.security;

import com.lattice.oidc.common.Caches;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.UserStore;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
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
 */
@Singleton
public final class UserSessions {

  public record LoginState(User user, String sessionId, long authTime, String acr) {}

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final String SESSION_ID = "session_id";
  private static final String BROWSER_ID = "browser_id";
  private static final String SUBJECT = "subject";
  private static final String AUTH_TIME = "auth_time";
  private static final String ACR = "acr";

  private record SessionRecord(String subject, Set<String> clients) {}

  private final SyncCacheApi cache;
  private final UserStore users;
  private final LatticeConfig config;

  @Inject
  public UserSessions(
      @NamedCache(Caches.SESSIONS) SyncCacheApi cache, UserStore users, LatticeConfig config) {
    this.cache = cache;
    this.users = users;
    this.config = config;
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
    if (record.isEmpty() || !record.get().subject().equals(subject.get())) {
      return Optional.empty();
    }
    long authTime;
    try {
      authTime = Long.parseLong(authTimeValue.get());
    } catch (NumberFormatException e) {
      return Optional.empty();
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

  /** Starts a new login session (new session ID, preventing session fixation). Returns the session ID. */
  public String login(User user, long authTime, String acr, Map<String, String> sessionOut) {
    String sessionId = randomId();
    cache.set(
        key(sessionId),
        new SessionRecord(user.getSubject(), new LinkedHashSet<>()),
        (int) config.sessionMaxLifespan().toSeconds());
    sessionOut.put(SESSION_ID, sessionId);
    sessionOut.put(SUBJECT, user.getSubject());
    sessionOut.put(AUTH_TIME, Long.toString(authTime));
    sessionOut.put(ACR, acr == null ? "" : acr);
    return sessionId;
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
              synchronized (record.clients()) {
                record.clients().add(clientIdentifier);
              }
            });
  }

  public Set<String> clients(String sessionId) {
    return cache.<SessionRecord>get(key(sessionId))
        .map(
            record -> {
              synchronized (record.clients()) {
                return Set.copyOf(record.clients());
              }
            })
        .orElse(Set.of());
  }

  /** Ends the login session server-side and strips it from the cookie (keeps the browser id). */
  public Result logout(Result result, Http.Request request, String sessionId) {
    if (sessionId != null) {
      cache.remove(key(sessionId));
    }
    return result.removingFromSession(request, SESSION_ID, SUBJECT, AUTH_TIME, ACR);
  }

  private static String key(String sessionId) {
    return "session:" + sessionId;
  }
}

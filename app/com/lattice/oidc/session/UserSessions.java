package com.lattice.oidc.session;

import com.lattice.oidc.config.LatticeConfig;
import com.lattice.oidc.user.User;
import com.lattice.oidc.user.UserStore;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.inject.Inject;
import javax.inject.Singleton;
import play.cache.SyncCacheApi;
import play.mvc.Http;
import play.mvc.Result;

/**
 * Browser login sessions.
 *
 * <p>The signed Play session cookie carries only identifiers: {@code bid} (a stable browser
 * binding for pending interactions), {@code sid} (the login session, rotated at every login) and
 * {@code sub}/{@code auth_time}. A session is valid only while its {@code sid} is registered
 * server-side, so logout invalidates it even if the cookie is replayed.
 */
@Singleton
public final class UserSessions {

  public record LoginState(User user, String sid, long authTime, String acr) {}

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final String SID = "sid";
  private static final String BID = "bid";
  private static final String SUB = "sub";
  private static final String AUTH_TIME = "auth_time";
  private static final String ACR = "acr";

  private record SessionRecord(String subject, Set<String> clients) {}

  private final SyncCacheApi cache;
  private final UserStore users;
  private final LatticeConfig config;

  @Inject
  public UserSessions(SyncCacheApi cache, UserStore users, LatticeConfig config) {
    this.cache = cache;
    this.users = users;
    this.config = config;
  }

  public static String randomId() {
    byte[] b = new byte[32];
    RANDOM.nextBytes(b);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  /** The logged-in user, if the session is still registered and within its maximum lifetime. */
  public Optional<LoginState> current(Http.Request request) {
    Http.Session s = request.session();
    Optional<String> sid = s.get(SID);
    Optional<String> sub = s.get(SUB);
    Optional<String> authTime = s.get(AUTH_TIME);
    if (sid.isEmpty() || sub.isEmpty() || authTime.isEmpty()) {
      return Optional.empty();
    }
    Optional<SessionRecord> record = cache.get(key(sid.get()));
    if (record.isEmpty() || !record.get().subject().equals(sub.get())) {
      return Optional.empty();
    }
    long at;
    try {
      at = Long.parseLong(authTime.get());
    } catch (NumberFormatException e) {
      return Optional.empty();
    }
    return users
        .bySubject(sub.get())
        .map(
            u ->
                new LoginState(
                    u, sid.get(), at, s.get(ACR).filter(a -> !a.isEmpty()).orElse(null)));
  }

  /** Whether a login session id is still active (used by native SSO). */
  public boolean isActive(String sid) {
    return sid != null && cache.get(key(sid)).isPresent();
  }

  /** The stable browser binding, generating one if absent (persist it with {@link #withBid}). */
  public String bid(Http.Request request) {
    return request.session().get(BID).orElseGet(UserSessions::randomId);
  }

  public Result withBid(Result result, Http.Request request, String bid) {
    return result.addingToSession(request, BID, bid);
  }

  /** Starts a new login session (new sid, preventing session fixation). Returns the new sid. */
  public String login(User user, long authTime, String acr, Map<String, String> sessionOut) {
    String sid = randomId();
    cache.set(
        key(sid),
        new SessionRecord(user.getSubject(), new LinkedHashSet<>()),
        (int) config.sessionMaxLifespan().toSeconds());
    sessionOut.put(SID, sid);
    sessionOut.put(SUB, user.getSubject());
    sessionOut.put(AUTH_TIME, Long.toString(authTime));
    sessionOut.put(ACR, acr == null ? "" : acr);
    return sid;
  }

  /** Applies session values produced by {@link #login} (and the browser binding) to a result. */
  public Result apply(Result result, Http.Request request, Map<String, String> values) {
    if (values.isEmpty()) {
      return result;
    }
    return result.addingToSession(request, values);
  }

  /** Records that a client obtained tokens in this session (for back-channel logout). */
  public void addClient(String sid, String clientIdentifier) {
    if (sid == null || clientIdentifier == null) {
      return;
    }
    cache.<SessionRecord>get(key(sid))
        .ifPresent(
            r -> {
              synchronized (r.clients()) {
                r.clients().add(clientIdentifier);
              }
            });
  }

  public Set<String> clients(String sid) {
    return cache.<SessionRecord>get(key(sid))
        .map(
            r -> {
              synchronized (r.clients()) {
                return Set.copyOf(r.clients());
              }
            })
        .orElse(Set.of());
  }

  /** Ends the login session server-side and strips it from the cookie (keeps the browser id). */
  public Result logout(Result result, Http.Request request, String sid) {
    if (sid != null) {
      cache.remove(key(sid));
    }
    return result.removingFromSession(request, SID, SUB, AUTH_TIME, ACR);
  }

  private static String key(String sid) {
    return "session:" + sid;
  }
}

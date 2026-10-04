package com.lattice.oidc.security;

import com.lattice.oidc.common.Caches;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.inject.Inject;
import javax.inject.Singleton;
import play.cache.NamedCache;
import play.cache.SyncCacheApi;

/**
 * "New sign-in to your account" alerts: raised when an account signs in from a browser it has not
 * used before (and it has signed in somewhere before), shown on the account page of the account's
 * other sessions until the user answers "it was me" or "secure my account".
 */
@Singleton
public final class SignInAlerts {

  /** A sign-in from a new browser. */
  public record Alert(String id, String sessionId, String device, String ip, String method, Instant at) {
    private static final DateTimeFormatter TIME =
        DateTimeFormatter.ofPattern("d MMM, HH:mm 'UTC'", Locale.ENGLISH).withZone(ZoneOffset.UTC);

    public String when() {
      return TIME.format(at);
    }
  }

  /** Alerts and known browsers are kept for 30 days. */
  private static final int TTL = 30 * 24 * 3600;

  private final SyncCacheApi cache;

  @Inject
  public SignInAlerts(@NamedCache(Caches.SESSIONS) SyncCacheApi cache) {
    this.cache = cache;
  }

  synchronized void onSignIn(String subject, String browserId, String sessionId, String device, String ip, String method) {
    Set<String> known = cache.<Set<String>>get(browsersKey(subject)).orElseGet(ConcurrentHashMap::newKeySet);
    boolean firstSignIn = known.isEmpty();
    if (known.add(browserId) && !firstSignIn) {
      List<Alert> alerts = new ArrayList<>(cache.<List<Alert>>get(alertsKey(subject)).orElse(List.of()));
      alerts.add(new Alert(UserSessions.randomId(), sessionId, device, ip, method, Instant.now()));
      cache.set(alertsKey(subject), List.copyOf(alerts), TTL);
    }
    cache.set(browsersKey(subject), known, TTL);
  }

  /** Alerts to show in session {@code currentSessionId}: those raised by other sessions. */
  public List<Alert> pending(String subject, String currentSessionId) {
    return cache.<List<Alert>>get(alertsKey(subject)).orElse(List.of()).stream()
        .filter(alert -> !alert.sessionId().equals(currentSessionId))
        .toList();
  }

  /** Removes the alert (the user answered it); returns it if it existed. */
  public synchronized Optional<Alert> resolve(String subject, String alertId) {
    List<Alert> alerts = new ArrayList<>(cache.<List<Alert>>get(alertsKey(subject)).orElse(List.of()));
    Optional<Alert> found = alerts.stream().filter(alert -> alert.id().equals(alertId)).findFirst();
    found.ifPresent(alerts::remove);
    cache.set(alertsKey(subject), List.copyOf(alerts), TTL);
    return found;
  }

  private static String alertsKey(String subject) {
    return "signin-alerts:" + subject;
  }

  private static String browsersKey(String subject) {
    return "known-browsers:" + subject;
  }
}

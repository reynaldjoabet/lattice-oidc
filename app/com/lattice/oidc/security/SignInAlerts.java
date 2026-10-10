package com.lattice.oidc.security;

import com.lattice.oidc.common.Digests;
import com.lattice.oidc.common.JsonHelpers;
import com.lattice.oidc.stores.EphemeralStore;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/**
 * "New sign-in to your account" alerts: raised when an account signs in from a browser it has not
 * used before (and it has signed in somewhere before), shown on the account page of the account's
 * other sessions until the user answers "it was me" or "secure my account". Known browsers are
 * stored by a hash of their browser id, which acts as a credential.
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
  private static final Duration TTL = Duration.ofDays(30);

  private static final String BROWSERS = "known-browser";
  private static final String ALERTS = "signin-alert";

  private final EphemeralStore store;

  @Inject
  public SignInAlerts(EphemeralStore store) {
    this.store = store;
  }

  void onSignIn(String subject, String browserId, String sessionId, String device, String ip, String method) {
    String browserKey = subject + "|" + Digests.sha256Base64Url(browserId);
    boolean firstSignIn = store.bySubject(BROWSERS, subject).isEmpty();
    boolean newBrowser = store.get(BROWSERS, browserKey).isEmpty();
    store.put(BROWSERS, browserKey, null, subject, "{}", TTL);
    if (newBrowser && !firstSignIn) {
      Alert alert = new Alert(UserSessions.randomId(), sessionId, device, ip, method, Instant.now());
      store.put(ALERTS, alert.id(), null, subject, JsonHelpers.write(alert), TTL);
    }
  }

  /** Alerts to show in session {@code currentSessionId}: those raised by other sessions. */
  public List<Alert> pending(String subject, String currentSessionId) {
    return store.bySubject(ALERTS, subject).stream()
        .map(entry -> JsonHelpers.read(entry.json(), Alert.class))
        .filter(alert -> !alert.sessionId().equals(currentSessionId))
        .sorted(Comparator.comparing(Alert::at))
        .toList();
  }

  /** Removes the alert (the user answered it); returns it if it existed and was the account's. */
  public Optional<Alert> resolve(String subject, String alertId) {
    if (alertId == null || store.get(ALERTS, alertId).filter(entry -> subject.equals(entry.subject())).isEmpty()) {
      return Optional.empty();
    }
    return store.take(ALERTS, alertId).map(entry -> JsonHelpers.read(entry.json(), Alert.class));
  }
}

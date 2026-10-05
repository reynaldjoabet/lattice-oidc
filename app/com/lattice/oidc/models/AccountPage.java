package com.lattice.oidc.models;

import com.lattice.oidc.security.SignInAlerts;
import java.util.List;
import java.util.Optional;

/**
 * The end-user's account page: profile, the apps holding access (removable), sign-in methods, CIBA
 * requests waiting for a decision, passkeys, the number of active sessions and the sign-in alerts
 * ("was this you?") raised by other sessions.
 */
public record AccountPage(
    String name,
    Optional<String> email,
    List<App> apps,
    boolean appsUnavailable,
    List<SignInMethod> signInMethods,
    int waitingRequests,
    boolean admin,
    List<Passkey> passkeys,
    int sessionCount,
    List<SignInAlerts.Alert> alerts,
    TwoStep twoStep) {

  /** Two-step verification: whether an authenticator app is set up, and recovery codes left. */
  public record TwoStep(boolean authenticatorApp, int recoveryCodesLeft, boolean hasPassword) {}


  /** An app the user has authorized (Authlete client authorization). */
  public record App(long clientId, String name, Optional<String> logoUri, Optional<String> uri) {
    public String initials() {
      return Initials.of(name);
    }
  }

  /** A way to sign in to this account: password or a linked upstream provider. */
  public record SignInMethod(String name, String detail) {}

  public String initial() {
    return Initials.of(name).substring(0, 1);
  }
}

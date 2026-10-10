package com.lattice.oidc.security;

import com.lattice.oidc.common.Digests;
import com.lattice.oidc.common.JsonHelpers;
import com.lattice.oidc.common.Mailer;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.CounterStore;
import com.lattice.oidc.stores.EphemeralStore;
import com.lattice.oidc.stores.UserStore;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.function.Function;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/**
 * Email verification links (the {@code VERIFY_EMAIL} required action). A link carries a random
 * token, only its hash is stored, it works once within a day, and only the newest link works. An
 * account can request 3 links per 15 minutes. Opening the link verifies the email whether or not the
 * browser is signed in, so it works from a mail app on another device.
 *
 * <p>A link proves control of one address: the one it was sent to. It is stored with that address
 * and verifies nothing if the account's email has changed since (an LDAP sync, a brokered sign-in or
 * an edit), because the new address was never proven.
 */
@Singleton
public final class EmailVerification {

  private static final String TOKENS = "verify-email";
  private static final Duration LINK_LIFETIME = Duration.ofDays(1);
  private static final int MAX_REQUESTS = 3;
  private static final Duration WINDOW = Duration.ofMinutes(15);
  private static final SecureRandom RANDOM = new SecureRandom();

  private final EphemeralStore store;
  private final CounterStore counters;
  private final UserStore users;
  private final Mailer mailer;
  private final RequiredActions actions;

  @Inject
  public EmailVerification(
      EphemeralStore store, CounterStore counters, UserStore users, Mailer mailer, RequiredActions actions) {
    this.store = store;
    this.counters = counters;
    this.users = users;
    this.mailer = mailer;
    this.actions = actions;
  }

  /**
   * Emails a verification link to the account's address, unless the account is over its rate limit.
   * {@code link} builds the link's URL from the token.
   *
   * @return whether a link was sent
   */
  public boolean send(User user, Function<String, String> link) {
    Optional<String> email = user.email();
    if (email.isEmpty() || counters.increment("verify-email:" + user.getSubject(), WINDOW) > MAX_REQUESTS) {
      return false;
    }
    byte[] bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    store.deleteBySubject(TOKENS, user.getSubject());
    store.put(TOKENS, Digests.sha256Base64Url(token), null, user.getSubject(), JsonHelpers.write(new Sent(email.get())), LINK_LIFETIME);
    mailer.send(
        email.get(),
        "Verify your email",
        "Hello " + user.displayName() + ",\n\n"
            + "To confirm this is your email address, open this link:\n\n"
            + link.apply(token) + "\n\n"
            + "The link works once and expires in 24 hours. If you didn't ask for this, ignore this email.\n");
    return true;
  }

  /** The address a link was sent to. */
  public record Sent(String email) {}

  /**
   * Verifies the email of the link's account and uses the link up; empty if the link is unknown or
   * used, or if the account's email is no longer the address the link was sent to.
   */
  public Optional<User> verify(String token) {
    if (token == null || token.isEmpty()) {
      return Optional.empty();
    }
    Optional<EphemeralStore.Entry> entry = store.take(TOKENS, Digests.sha256Base64Url(token));
    if (entry.isEmpty()) {
      return Optional.empty();
    }
    // Links sent before addresses were recorded hold "{}": they verify nothing, so a new one is needed.
    String sentTo = JsonHelpers.read(entry.get().json(), Sent.class).email();
    Optional<User> user =
        users.bySubject(entry.get().subject()).filter(account -> sameAddress(account.email(), sentTo));
    user.ifPresent(actions::markEmailVerified);
    return user;
  }

  /** Whether the account's current email is still {@code sentTo} (addresses compare case-insensitively). */
  static boolean sameAddress(Optional<String> current, String sentTo) {
    return sentTo != null && current.map(email -> email.trim().equalsIgnoreCase(sentTo.trim())).orElse(false);
  }
}

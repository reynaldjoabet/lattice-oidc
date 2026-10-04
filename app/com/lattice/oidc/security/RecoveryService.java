package com.lattice.oidc.security;

import com.lattice.oidc.common.Caches;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.common.Mailer;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.UserStore;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;
import java.util.function.Function;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.cache.NamedCache;
import play.cache.SyncCacheApi;

/**
 * Password reset links ({@code lattice.recovery}). A link carries a random token; only its SHA-256
 * is stored, it works once, expires after {@code link-lifetime}, and only the account's newest
 * link works. At most {@code max-requests} links are sent per account per {@code window}.
 * Callers show the same page whether or not an account matched, so the form reveals nothing.
 */
@Singleton
public final class RecoveryService {

  private static final Logger LOG = LoggerFactory.getLogger(RecoveryService.class);
  private static final SecureRandom RANDOM = new SecureRandom();

  /** A link waiting to be used: whose password it resets, and where to continue afterwards. */
  public record Pending(String subject, String next) implements java.io.Serializable {}

  private final SyncCacheApi cache;
  private final LoginService login;
  private final UserStore users;
  private final Mailer mailer;
  private final LatticeConfig.Recovery config;

  @Inject
  public RecoveryService(
      @NamedCache(Caches.INTERACTIONS) SyncCacheApi cache,
      LoginService login,
      UserStore users,
      Mailer mailer,
      LatticeConfig config) {
    this.cache = cache;
    this.login = login;
    this.users = users;
    this.mailer = mailer;
    this.config = config.recovery();
  }

  /**
   * Emails a reset link if {@code identifier} is an account with an email address and the account
   * is under its rate limit. {@code link} builds the link's URL from the token.
   *
   * @return whether a link was sent (for the audit log only; never shown)
   */
  public boolean request(String identifier, String next, Function<String, String> link) {
    Optional<User> user = login.find(identifier == null ? null : identifier.trim());
    if (user.isEmpty() || user.get().email().isEmpty() || user.get().passwordHash() == null) {
      return false;
    }
    String subject = user.get().getSubject();
    String countKey = "recovery-requests:" + subject;
    int sent = cache.<Integer>get(countKey).orElse(0);
    if (sent >= config.maxRequests()) {
      LOG.info("Password reset rate limit reached for {}", subject);
      return false;
    }
    cache.set(countKey, sent + 1, (int) config.window().toSeconds());

    String token = randomToken();
    String hash = sha256(token);
    int lifetime = (int) config.linkLifetime().toSeconds();
    cache.<String>get(currentKey(subject)).ifPresent(previous -> cache.remove(tokenKey(previous)));
    cache.set(tokenKey(hash), new Pending(subject, next), lifetime);
    cache.set(currentKey(subject), hash, lifetime);

    long minutes = config.linkLifetime().toMinutes();
    mailer.send(
        user.get().email().get(),
        "Reset your password",
        "Hello " + user.get().displayName() + ",\n\n"
            + "Someone asked to reset the password for your account. To choose a new password, open this link:\n\n"
            + link.apply(token) + "\n\n"
            + "The link works once and expires in " + minutes + " minutes.\n"
            + "If you didn't ask for this, ignore this email: your password stays the same.\n");
    return true;
  }

  /** The account a link resets, without using it up (to show the form). */
  public Optional<Pending> peek(String token) {
    return token == null || token.isEmpty() ? Optional.empty() : cache.get(tokenKey(sha256(token)));
  }

  /** Sets the new password and uses the link up. Empty if the link has expired or was used. */
  public synchronized Optional<User> reset(String token, String newPassword) {
    Optional<Pending> pending = peek(token);
    if (pending.isEmpty()) {
      return Optional.empty();
    }
    Optional<User> user = users.bySubject(pending.get().subject());
    cache.remove(tokenKey(sha256(token)));
    cache.remove(currentKey(pending.get().subject()));
    if (user.isEmpty()) {
      return Optional.empty();
    }
    User updated = user.get().withPasswordHash(PasswordPolicy.hash(newPassword));
    users.save(updated);
    login.unlock(updated);
    return Optional.of(updated);
  }

  public long linkLifetimeMinutes() {
    return config.linkLifetime().toMinutes();
  }

  private static String tokenKey(String hash) {
    return "recovery:" + hash;
  }

  private static String currentKey(String subject) {
    return "recovery-current:" + subject;
  }

  private static String randomToken() {
    byte[] bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private static String sha256(String value) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}

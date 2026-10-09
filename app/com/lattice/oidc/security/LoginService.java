package com.lattice.oidc.security;

import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.CounterStore;
import com.lattice.oidc.stores.UserStore;
import com.password4j.Password;
import java.util.Locale;
import java.util.Optional;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Password authentication with brute-force protection. Failures are counted over {@code
 * lattice.login.lockout} in three ways, and reaching any limit refuses further attempts until the
 * window ends:
 *
 * <ul>
 *   <li>for one account from one IP address ({@code max-failures}),
 *   <li>for one account from any IP address ({@code max-failures-per-account}),
 *   <li>from one IP address for any accounts ({@code max-failures-per-ip}, password spraying).
 * </ul>
 *
 * Counting per account and IP first means someone guessing from elsewhere can't lock the real user
 * out with a handful of attempts. Unknown accounts cost the same hash verification as known ones,
 * so timing does not reveal which exist. Counters are kept in the {@link CounterStore}, shared by
 * every server.
 *
 * <p>With an LDAP directory ({@link LdapDirectory}), an identifier that isn't a local account, or is
 * one that came from the directory, is checked against the directory instead. A local account with
 * the same login ID takes precedence.
 */
@Singleton
public final class LoginService {

  public enum Outcome {
    SUCCESS,
    INVALID_CREDENTIALS,
    LOCKED,
    /** The LDAP directory couldn't be reached; not counted as a failed attempt. */
    UNAVAILABLE
  }

  public record Result(Outcome outcome, Optional<User> user) {}

  /** Prefix of the per-account counters (the operator console counts them). */
  public static final String ACCOUNT_PREFIX = "login:account:";

  private static final Logger LOG = LoggerFactory.getLogger(LoginService.class);
  private static final String DUMMY_HASH =
      Password.hash("lattice-dummy-password").addRandomSalt().withArgon2().getResult();

  private final UserStore users;
  private final CounterStore counters;
  private final LatticeConfig config;
  private final LdapDirectory directory;

  @Inject
  public LoginService(
      UserStore users,
      CounterStore counters,
      LatticeConfig config,
      LdapDirectory directory,
      com.typesafe.config.Config rawConfig) {
    int concurrency = rawConfig.getInt("lattice.login.hashing-concurrency");
    PasswordHasher.configure(concurrency > 0 ? concurrency : PasswordHasher.defaultConcurrency());
    this.users = users;
    this.counters = counters;
    this.config = config;
    this.directory = directory;
  }

  /** Clears failed sign-in attempts for the account (after its password is reset). */
  public void unlock(User user) {
    if (user.loginId() != null) {
      clear(user.loginId());
    }
    user.email().ifPresent(this::clear);
  }

  private void clear(String identifier) {
    String normalized = identifier.trim().toLowerCase(Locale.ROOT);
    counters.reset(ACCOUNT_PREFIX + normalized);
    counters.resetPrefix(accountAndIpPrefix(normalized));
  }

  /** The account for a login ID, or for an email address (sign-in accepts either). */
  public Optional<User> find(String identifier) {
    if (identifier == null || identifier.isBlank()) {
      return Optional.empty();
    }
    Optional<User> byLoginId = users.byLoginId(identifier);
    return byLoginId.isPresent() || identifier.indexOf('@') < 0 ? byLoginId : users.byEmail(identifier);
  }

  /** As {@link #authenticate(String, String, String)} without an IP address (internal callers). */
  public Result authenticate(String loginId, String password) {
    return authenticate(loginId, password, null);
  }

  /** Checks a password, counting failures per account, per account and IP, and per IP. */
  public Result authenticate(String loginId, String password, String ip) {
    if (loginId == null || loginId.isBlank() || password == null || password.isEmpty()) {
      return new Result(Outcome.INVALID_CREDENTIALS, Optional.empty());
    }
    String identifier = loginId.trim().toLowerCase(Locale.ROOT);
    String accountKey = ACCOUNT_PREFIX + identifier;
    String accountAndIpKey = ip == null ? null : accountAndIpPrefix(identifier) + ip;
    String ipKey = ip == null ? null : "login:ip:" + ip;
    if (locked(accountKey, accountAndIpKey, ipKey)) {
      return new Result(Outcome.LOCKED, Optional.empty());
    }

    Optional<User> user = find(loginId.trim());
    Optional<User> authenticated;
    if (directory.enabled() && (user.isEmpty() || LdapDirectory.isFederated(user.get()))) {
      try {
        authenticated = directory.authenticate(loginId.trim(), password);
      } catch (LdapDirectory.Unavailable e) {
        LOG.warn("Sign-in for '{}' could not reach the LDAP directory: {}", loginId, e.getMessage());
        return new Result(Outcome.UNAVAILABLE, Optional.empty());
      }
    } else {
      String hash = user.map(User::passwordHash).orElse(null);
      boolean ok = PasswordHasher.check(password, hash != null ? hash : DUMMY_HASH);
      authenticated = ok && hash != null ? user : Optional.empty();
    }
    if (authenticated.isPresent()) {
      counters.reset(accountKey);
      if (accountAndIpKey != null) {
        counters.reset(accountAndIpKey);
      }
      return new Result(Outcome.SUCCESS, authenticated);
    }

    counters.increment(accountKey, config.loginLockout());
    if (accountAndIpKey != null) {
      counters.increment(accountAndIpKey, config.loginLockout());
      counters.increment(ipKey, config.loginLockout());
    }
    if (locked(accountKey, accountAndIpKey, ipKey)) {
      LOG.warn("Sign-in locked for '{}' from {} after repeated failures", loginId, ip);
      return new Result(Outcome.LOCKED, Optional.empty());
    }
    return new Result(Outcome.INVALID_CREDENTIALS, Optional.empty());
  }

  private boolean locked(String accountKey, String accountAndIpKey, String ipKey) {
    if (accountAndIpKey == null) {
      // No IP address (internal callers): the limit for one source applies to the account.
      return counters.count(accountKey) >= config.loginMaxFailures();
    }
    return counters.count(accountAndIpKey) >= config.loginMaxFailures()
        || counters.count(accountKey) >= config.loginMaxFailuresPerAccount()
        || counters.count(ipKey) >= config.loginMaxFailuresPerIp();
  }

  private static String accountAndIpPrefix(String identifier) {
    return "login:account-ip:" + identifier + "|";
  }
}

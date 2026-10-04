package com.lattice.oidc.security;

import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.CounterStore;
import com.lattice.oidc.stores.UserStore;
import com.password4j.Password;
import java.util.Locale;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Singleton;
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
 */
@Singleton
public final class LoginService {

  public enum Outcome {
    SUCCESS,
    INVALID_CREDENTIALS,
    LOCKED
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

  @Inject
  public LoginService(UserStore users, CounterStore counters, LatticeConfig config) {
    this.users = users;
    this.counters = counters;
    this.config = config;
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
    String hash = user.map(User::passwordHash).orElse(null);
    boolean ok = Password.check(password, hash != null ? hash : DUMMY_HASH).withArgon2();
    if (ok && hash != null) {
      counters.reset(accountKey);
      if (accountAndIpKey != null) {
        counters.reset(accountAndIpKey);
      }
      return new Result(Outcome.SUCCESS, user);
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

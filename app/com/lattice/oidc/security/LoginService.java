package com.lattice.oidc.security;

import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.UserStore;
import com.password4j.Password;
import java.util.Locale;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.cache.SyncCacheApi;

/**
 * Password authentication with brute-force protection: after {@code lattice.login.max-failures}
 * consecutive failures an account is locked for {@code lattice.login.lockout}. Unknown accounts
 * cost the same hash verification as known ones, so timing does not reveal which exist.
 */
@Singleton
public final class LoginService {

  public enum Outcome {
    SUCCESS,
    INVALID_CREDENTIALS,
    LOCKED
  }

  public record Result(Outcome outcome, Optional<User> user) {}

  private static final Logger LOG = LoggerFactory.getLogger(LoginService.class);
  private static final String DUMMY_HASH =
      Password.hash("lattice-dummy-password").addRandomSalt().withArgon2().getResult();

  private final UserStore users;
  private final SyncCacheApi cache;
  private final LatticeConfig config;

  @Inject
  public LoginService(UserStore users, SyncCacheApi cache, LatticeConfig config) {
    this.users = users;
    this.cache = cache;
    this.config = config;
  }

  public Result authenticate(String loginId, String password) {
    if (loginId == null || loginId.isBlank() || password == null || password.isEmpty()) {
      return new Result(Outcome.INVALID_CREDENTIALS, Optional.empty());
    }
    String key = "login-failures:" + loginId.trim().toLowerCase(Locale.ROOT);
    int failures = cache.<Integer>get(key).orElse(0);
    if (failures >= config.loginMaxFailures()) {
      return new Result(Outcome.LOCKED, Optional.empty());
    }

    Optional<User> user = users.byLoginId(loginId.trim());
    String hash = user.map(User::passwordHash).orElse(null);
    boolean ok = Password.check(password, hash != null ? hash : DUMMY_HASH).withArgon2();
    if (ok && hash != null) {
      cache.remove(key);
      return new Result(Outcome.SUCCESS, user);
    }

    failures++;
    cache.set(key, failures, (int) config.loginLockout().toSeconds());
    if (failures >= config.loginMaxFailures()) {
      LOG.warn("Login locked for '{}' after {} failed attempts", loginId, failures);
      return new Result(Outcome.LOCKED, Optional.empty());
    }
    return new Result(Outcome.INVALID_CREDENTIALS, Optional.empty());
  }
}

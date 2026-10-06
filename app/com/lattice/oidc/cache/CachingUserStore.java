package com.lattice.oidc.cache;

import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.metrics.Metrics;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.UserStore;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Singleton;

/**
 * Caches the lookup made on every signed-in request, a user by subject. Saving a user (a new
 * password, for example) invalidates it on every server. Lookups by login ID, email and phone
 * number only happen when signing in, so they always go to the store.
 *
 * <p>The cached copy includes the password hash, as the store's does; with {@code lattice.cache =
 * redis}, secure Redis like the database.
 */
@Singleton
public final class CachingUserStore implements UserStore {

  static final String REGION = "user";

  /** A user as cached (the {@link User} class itself isn't a plain data type). */
  private record Cached(
      String subject,
      String loginId,
      String passwordHash,
      Map<String, Object> claims,
      Map<String, Object> attributes,
      List<Map<String, Object>> verifiedClaims) {

    static Cached of(User user) {
      return new Cached(
          user.getSubject(), user.loginId(), user.passwordHash(), user.claims(), user.attributes(), user.verifiedClaims());
    }

    User user() {
      return new User(subject, loginId, passwordHash, claims, attributes, verifiedClaims);
    }
  }

  private final UserStore store;
  private final ReadCache cache;
  private final Metrics metrics;

  @Inject
  public CachingUserStore(@Named("backing") UserStore store, ReadCache cache, Metrics metrics) {
    this.store = store;
    this.cache = cache;
    this.metrics = metrics;
  }

  @Override
  public Optional<User> bySubject(String subject) {
    if (subject == null) {
      return Optional.empty();
    }
    Optional<String> cached = cache.get(REGION, subject);
    metrics.cacheLookup(REGION, cached.isPresent());
    if (cached.isPresent()) {
      return Optional.of(Jsons.read(cached.get(), Cached.class).user());
    }
    Optional<User> user = store.bySubject(subject);
    user.ifPresent(found -> cache.put(REGION, subject, Jsons.write(Cached.of(found))));
    return user;
  }

  @Override
  public Optional<User> byLoginId(String loginId) {
    return store.byLoginId(loginId);
  }

  @Override
  public Optional<User> byEmail(String email) {
    return store.byEmail(email);
  }

  @Override
  public Optional<User> byPhoneNumber(String phoneNumber) {
    return store.byPhoneNumber(phoneNumber);
  }

  @Override
  public void save(User user) {
    store.save(user);
    cache.invalidate(REGION, user.getSubject());
  }

  @Override
  public long count() {
    return store.count();
  }
}

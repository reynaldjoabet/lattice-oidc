package com.lattice.oidc.user;

import com.lattice.oidc.config.LatticeConfig;
import com.lattice.oidc.http.Jsons;
import com.password4j.Password;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.Environment;

/**
 * Thread-safe in-memory account store. When {@code lattice.demo-users} is on, it is seeded from
 * {@code conf/demo-users.json} with Argon2-hashed passwords.
 */
@Singleton
public final class InMemoryUserStore implements UserStore {

  private static final Logger LOG = LoggerFactory.getLogger(InMemoryUserStore.class);

  private final Map<String, User> bySubject = new ConcurrentHashMap<>();

  @Inject
  public InMemoryUserStore(LatticeConfig config, Environment environment) {
    if (config.demoUsers()) {
      seed(environment);
    }
  }

  @SuppressWarnings("unchecked")
  private void seed(Environment environment) {
    Map<String, Object> root = Jsons.readMap(resource(environment, "demo-users.json"));
    for (Object o : (List<Object>) root.get("users")) {
      Map<String, Object> u = (Map<String, Object>) o;
      List<Map<String, Object>> datasets = new ArrayList<>();
      for (Object file : (List<Object>) u.getOrDefault("verifiedClaims", List.of())) {
        Map<String, Object> doc = Jsons.readMap(resource(environment, (String) file));
        datasets.add((Map<String, Object>) doc.get("verified_claims"));
      }
      save(
          new User(
              (String) u.get("subject"),
              (String) u.get("loginId"),
              Password.hash((String) u.get("password")).addRandomSalt().withArgon2().getResult(),
              (Map<String, Object>) u.get("claims"),
              (Map<String, Object>) u.get("attributes"),
              datasets));
    }
    LOG.warn("Seeded {} DEMO user accounts; disable lattice.demo-users in production.", bySubject.size());
  }

  private static String resource(Environment environment, String name) {
    try (InputStream in = environment.resourceAsStream(name)) {
      if (in == null) {
        throw new IllegalStateException("Missing resource: " + name);
      }
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new IllegalStateException("Cannot read resource: " + name, e);
    }
  }

  private Optional<User> find(Predicate<User> predicate) {
    return bySubject.values().stream().filter(predicate).findFirst();
  }

  @Override
  public Optional<User> bySubject(String subject) {
    return subject == null ? Optional.empty() : Optional.ofNullable(bySubject.get(subject));
  }

  @Override
  public Optional<User> byLoginId(String loginId) {
    if (loginId == null) {
      return Optional.empty();
    }
    String wanted = loginId.toLowerCase(Locale.ROOT);
    return find(u -> u.loginId() != null && u.loginId().toLowerCase(Locale.ROOT).equals(wanted));
  }

  @Override
  public Optional<User> byEmail(String email) {
    return email == null
        ? Optional.empty()
        : find(u -> email.equalsIgnoreCase(String.valueOf(u.getClaim("email", null))));
  }

  @Override
  public Optional<User> byPhoneNumber(String phoneNumber) {
    return phoneNumber == null
        ? Optional.empty()
        : find(u -> phoneNumber.equals(u.getClaim("phone_number", null)));
  }

  @Override
  public void save(User user) {
    bySubject.put(user.getSubject(), user);
  }
}

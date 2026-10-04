package com.lattice.oidc.stores;

import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.models.User;
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
      demoUsers(environment).forEach(this::save);
      LOG.warn("Seeded {} DEMO user accounts; disable lattice.demo-users in production.", bySubject.size());
    }
  }

  /** The demo accounts in {@code conf/demo-users.json}, with Argon2-hashed passwords. */
  @SuppressWarnings("unchecked")
  public static List<User> demoUsers(Environment environment) {
    List<User> users = new ArrayList<>();
    Map<String, Object> root = Jsons.readMap(resource(environment, "demo-users.json"));
    for (Object entry : (List<Object>) root.get("users")) {
      Map<String, Object> account = (Map<String, Object>) entry;
      List<Map<String, Object>> datasets = new ArrayList<>();
      for (Object file : (List<Object>) account.getOrDefault("verifiedClaims", List.of())) {
        Map<String, Object> doc = Jsons.readMap(resource(environment, (String) file));
        datasets.add((Map<String, Object>) doc.get("verified_claims"));
      }
      users.add(
          new User(
              (String) account.get("subject"),
              (String) account.get("loginId"),
              Password.hash((String) account.get("password")).addRandomSalt().withArgon2().getResult(),
              (Map<String, Object>) account.get("claims"),
              (Map<String, Object>) account.get("attributes"),
              datasets));
    }
    return users;
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
    return find(user -> user.loginId() != null && user.loginId().toLowerCase(Locale.ROOT).equals(wanted));
  }

  @Override
  public Optional<User> byEmail(String email) {
    return email == null
        ? Optional.empty()
        : find(user -> email.equalsIgnoreCase(String.valueOf(user.getClaim("email", null))));
  }

  @Override
  public Optional<User> byPhoneNumber(String phoneNumber) {
    return phoneNumber == null
        ? Optional.empty()
        : find(user -> phoneNumber.equals(user.getClaim("phone_number", null)));
  }

  @Override
  public long count() {
    return bySubject.size();
  }

  @Override
  public void save(User user) {
    bySubject.put(user.getSubject(), user);
  }
}

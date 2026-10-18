package com.lattice.oidc.stores.postgres;

import static com.lattice.oidc.OidcTestSupport.app;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.UserStore;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.Application;
import play.test.Helpers;

/**
 * {@link UserStore} with {@code lattice.storage = postgres}, against a real PostgreSQL with the
 * Flyway schema: whatever implements it (plain JDBC or JPA) must behave as pinned down here.
 */
public class PostgresUserStoreTest {

  private Map<String, Object> database;
  private Application app;
  private UserStore users;

  @Before
  public void start() {
    database = TestPostgres.newDatabase();
    app = start(Map.of("lattice.demo-users", false));
    users = app.injector().instanceOf(UserStore.class);
  }

  @After
  public void stop() {
    Helpers.stop(app);
  }

  private Application start(Map<String, Object> extra) {
    Map<String, Object> config = new HashMap<>(database);
    config.putAll(extra);
    Application started = app(new FakeAuthleteApi(), config);
    Helpers.start(started);
    return started;
  }

  private static User user(String subject, String loginId, String hash, Map<String, Object> claims) {
    return new User(subject, loginId, hash, claims, Map.of("department", "Sales"),
        List.of(Map.of("verification", Map.of("trust_framework", "eidas"), "claims", Map.of("given_name", "Ann"))));
  }

  @Test
  public void theStoreIsTheDatabaseOne() {
    assertTrue(users.getClass().getSimpleName(), users.getClass().getSimpleName().startsWith("Postgres")
        || users.getClass().getSimpleName().startsWith("Jpa"));
  }

  @Test
  public void aSavedUserComesBackWithAllItsData() {
    User ann = user("2001", "ann", "$argon2id$hash", Map.of("email", "Ann@Example.com", "name", "Ann", "age", 41));
    users.save(ann);
    User loaded = users.bySubject("2001").orElseThrow();
    assertEquals("ann", loaded.loginId());
    assertEquals("$argon2id$hash", loaded.passwordHash());
    assertEquals(Map.of("email", "Ann@Example.com", "name", "Ann", "age", 41), loaded.claims());
    assertEquals(Map.of("department", "Sales"), loaded.attributes());
    assertEquals(ann.verifiedClaims(), loaded.verifiedClaims());
  }

  @Test
  public void savingAgainReplacesTheUser() {
    users.save(user("2001", "ann", "h1", Map.of("name", "Ann")));
    users.save(new User("2001", "annie", "h2", Map.of("name", "Annie"), Map.of(), List.of()));
    User loaded = users.bySubject("2001").orElseThrow();
    assertEquals("annie", loaded.loginId());
    assertEquals("h2", loaded.passwordHash());
    assertEquals(Map.of("name", "Annie"), loaded.claims());
    assertEquals(Map.of(), loaded.attributes());
    assertEquals(List.of(), loaded.verifiedClaims());
    assertEquals(1, users.count());
  }

  @Test
  public void loginIdsAreFoundIgnoringCase() {
    users.save(user("2001", "Ann.Smith", "h", Map.of()));
    assertEquals("2001", users.byLoginId("ann.smith").orElseThrow().getSubject());
    assertEquals("2001", users.byLoginId("ANN.SMITH").orElseThrow().getSubject());
    assertEquals(Optional.empty(), users.byLoginId("ann"));
  }

  @Test
  public void twoUsersCantShareALoginIdInAnyCase() {
    users.save(user("2001", "ann", "h", Map.of()));
    assertThrows(RuntimeException.class, () -> users.save(user("2002", "ANN", "h", Map.of())));
  }

  @Test
  public void emailsAreFoundIgnoringCaseAndTheLowestSubjectWins() {
    users.save(user("2002", "b", "h", Map.of("email", "shared@example.com")));
    users.save(user("2001", "a", "h", Map.of("email", "Shared@Example.com")));
    assertEquals("2001", users.byEmail("SHARED@example.COM").orElseThrow().getSubject());
    assertEquals(Optional.empty(), users.byEmail("nobody@example.com"));
  }

  @Test
  public void phoneNumbersAreFoundExactly() {
    users.save(user("2001", "a", "h", Map.of("phone_number", "+44 20 7946 0000")));
    assertEquals("2001", users.byPhoneNumber("+44 20 7946 0000").orElseThrow().getSubject());
    assertEquals(Optional.empty(), users.byPhoneNumber("+442079460000"));
  }

  @Test
  public void aPasswordHashIsReplacedOnlyIfItIsStillTheExpectedOne() {
    users.save(user("2001", "ann", "old", Map.of()));
    assertFalse("a stale expected hash changes nothing", users.replacePasswordHash("2001", "stale", "new"));
    assertEquals("old", users.bySubject("2001").orElseThrow().passwordHash());
    assertTrue(users.replacePasswordHash("2001", "old", "new"));
    assertEquals("new", users.bySubject("2001").orElseThrow().passwordHash());
    assertFalse("an unknown user", users.replacePasswordHash("9999", "old", "new"));
  }

  @Test
  public void missingArgumentsFindNothing() {
    assertEquals(Optional.empty(), users.bySubject(null));
    assertEquals(Optional.empty(), users.byLoginId(null));
    assertEquals(Optional.empty(), users.byEmail(null));
    assertEquals(Optional.empty(), users.byPhoneNumber(null));
    assertFalse(users.replacePasswordHash(null, "a", "b"));
  }

  @Test
  public void demoUsersAreAddedOnlyToAnEmptyDatabase() {
    Helpers.stop(app);
    app = start(Map.of("lattice.demo-users", true));
    long seeded = app.injector().instanceOf(UserStore.class).count();
    assertTrue("demo users were added", seeded > 0);

    Helpers.stop(app);
    app = start(Map.of("lattice.demo-users", true));
    assertEquals("a second start adds nothing", seeded, app.injector().instanceOf(UserStore.class).count());
  }
}

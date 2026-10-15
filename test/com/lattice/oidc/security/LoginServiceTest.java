package com.lattice.oidc.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import com.lattice.oidc.OidcTestSupport;
import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.UserStore;
import java.util.Map;
import org.junit.Test;
import play.Application;
import play.test.Helpers;

public class LoginServiceTest {

  /** A hash from before the cost was raised (15 MiB), as the previous implementation wrote it. */
  private static String hashFromBeforeTheUpgrade(String password) {
    String hash = com.password4j.Password.hash(password).addRandomSalt().withArgon2().getResult();
    assertTrue(hash, hash.contains("m=15360,"));
    return hash;
  }

  @Test
  public void aHashFromBeforeTheUpgradeIsReplacedWhenItsOwnerSignsIn() {
    Application app = OidcTestSupport.app(new FakeAuthleteApi());
    Helpers.running(
        app,
        () -> {
          UserStore users = app.injector().instanceOf(UserStore.class);
          LoginService login = app.injector().instanceOf(LoginService.class);
          User max = users.byLoginId("max").orElseThrow();
          String old = hashFromBeforeTheUpgrade("max");
          users.save(max.withPasswordHash(old));

          assertEquals(LoginService.Outcome.INVALID_CREDENTIALS, login.authenticate("max", "wrong").outcome());
          assertEquals("a wrong password changes nothing", old, users.bySubject(max.getSubject()).orElseThrow().passwordHash());

          assertEquals(LoginService.Outcome.SUCCESS, login.authenticate("max", "max").outcome());
          String upgraded = users.bySubject(max.getSubject()).orElseThrow().passwordHash();
          assertNotEquals("replaced", old, upgraded);
          assertTrue(upgraded, upgraded.startsWith("$argon2id$v=19$m=19456,t=2,p=1$"));
          assertTrue("and it is the same password", PasswordHasher.check("max", upgraded));
          assertFalse(PasswordHasher.check("wrong", upgraded));

          assertEquals(LoginService.Outcome.SUCCESS, login.authenticate("max", "max").outcome());
          assertEquals("a current hash is not replaced again", upgraded, users.bySubject(max.getSubject()).orElseThrow().passwordHash());
        });
  }

  /**
   * The replacement is conditional: if the owner changed their password after the old one was verified
   * but before the upgrade was written, the new password must survive.
   */
  @Test
  public void aHashIsReplacedOnlyIfItIsStillTheOneThatWasVerified() {
    Application app = OidcTestSupport.app(new FakeAuthleteApi());
    Helpers.running(
        app,
        () -> {
          UserStore users = app.injector().instanceOf(UserStore.class);
          User max = users.byLoginId("max").orElseThrow();
          users.save(max.withPasswordHash("hash-A"));

          assertFalse("changed since it was checked", users.replacePasswordHash(max.getSubject(), "hash-OLD", "hash-B"));
          assertEquals("hash-A", users.bySubject(max.getSubject()).orElseThrow().passwordHash());
          assertTrue(users.replacePasswordHash(max.getSubject(), "hash-A", "hash-B"));
          assertEquals("hash-B", users.bySubject(max.getSubject()).orElseThrow().passwordHash());
          assertFalse("no such account", users.replacePasswordHash("nobody", "a", "b"));
          assertFalse(users.replacePasswordHash(max.getSubject(), null, "c"));
        });
  }

  @Test
  public void locksAccountAfterRepeatedFailures() {
    Application app = OidcTestSupport.app(new FakeAuthleteApi());
    Helpers.running(
        app,
        () -> {
          LoginService login = app.injector().instanceOf(LoginService.class);
          assertEquals(LoginService.Outcome.SUCCESS, login.authenticate("max", "max").outcome());
          for (int i = 0; i < 4; i++) {
            assertEquals(
                LoginService.Outcome.INVALID_CREDENTIALS, login.authenticate("MAX", "bad").outcome());
          }
          assertEquals(LoginService.Outcome.LOCKED, login.authenticate("max", "bad").outcome());
          assertEquals("even the right password is refused while locked",
              LoginService.Outcome.LOCKED, login.authenticate("max", "max").outcome());
          assertEquals(
              LoginService.Outcome.INVALID_CREDENTIALS, login.authenticate("ghost", "x").outcome());
        });
  }

  @Test
  public void guessingFromOneAddressDoesNotLockTheOwnerOutElsewhere() {
    Application app = OidcTestSupport.app(new FakeAuthleteApi());
    Helpers.running(
        app,
        () -> {
          LoginService login = app.injector().instanceOf(LoginService.class);
          for (int i = 0; i < 5; i++) {
            login.authenticate("max", "bad", "203.0.113.9");
          }
          assertEquals(
              "the guessing address is locked out",
              LoginService.Outcome.LOCKED,
              login.authenticate("max", "max", "203.0.113.9").outcome());
          assertEquals(
              "the owner signs in from their own address",
              LoginService.Outcome.SUCCESS,
              login.authenticate("max", "max", "198.51.100.7").outcome());
        });
  }

  @Test
  public void guessesFromManyAddressesStillLockTheAccount() {
    Application app =
        OidcTestSupport.app(new FakeAuthleteApi(), Map.of("lattice.login.max-failures-per-account", 6));
    Helpers.running(
        app,
        () -> {
          LoginService login = app.injector().instanceOf(LoginService.class);
          for (int i = 0; i < 6; i++) {
            login.authenticate("max", "bad", "203.0.113." + i);
          }
          assertEquals(
              LoginService.Outcome.LOCKED, login.authenticate("max", "max", "198.51.100.7").outcome());
        });
  }

  @Test
  public void sprayingManyAccountsFromOneAddressIsLimited() {
    Application app = OidcTestSupport.app(new FakeAuthleteApi(), Map.of("lattice.login.max-failures-per-ip", 3));
    Helpers.running(
        app,
        () -> {
          LoginService login = app.injector().instanceOf(LoginService.class);
          login.authenticate("john", "bad", "203.0.113.9");
          login.authenticate("jane", "bad", "203.0.113.9");
          login.authenticate("max", "bad", "203.0.113.9");
          assertEquals(
              "further attempts from the same address are refused",
              LoginService.Outcome.LOCKED,
              login.authenticate("john", "john", "203.0.113.9").outcome());
        });
  }

  @Test
  public void resettingThePasswordUnlocksTheAccount() {
    Application app = OidcTestSupport.app(new FakeAuthleteApi());
    Helpers.running(
        app,
        () -> {
          LoginService login = app.injector().instanceOf(LoginService.class);
          for (int i = 0; i < 5; i++) {
            login.authenticate("max", "bad", "203.0.113.9");
          }
          User max = app.injector().instanceOf(UserStore.class).byLoginId("max").orElseThrow();
          login.unlock(max);
          assertEquals(LoginService.Outcome.SUCCESS, login.authenticate("max", "max", "203.0.113.9").outcome());
        });
  }

  /** Raising the configured cost moves an account to it at its owner's next sign-in. */
  @Test
  public void aRaisedCostIsAppliedAtTheNextSignIn() {
    Application app =
        OidcTestSupport.app(new FakeAuthleteApi(), Map.of("lattice.login.argon2.memory-kib", 24_576));
    try {
      Helpers.running(
          app,
          () -> {
            UserStore users = app.injector().instanceOf(UserStore.class);
            LoginService login = app.injector().instanceOf(LoginService.class);
            User max = users.byLoginId("max").orElseThrow();
            String atDefault = "$argon2id$v=19$m=19456,t=2,p=1$BLsu3zxC5eXb3nouktgyYw$Li1yWpFfMWW1I00InB2XPkcFo56t+rHyoxTdgrfj5xQ";
            users.save(max.withPasswordHash(atDefault));
            assertEquals(LoginService.Outcome.SUCCESS, login.authenticate("max", "secret").outcome());
            String upgraded = users.bySubject(max.getSubject()).orElseThrow().passwordHash();
            assertTrue(upgraded, upgraded.startsWith("$argon2id$v=19$m=24576,t=2,p=1$"));
          });
    } finally {
      PasswordHasher.configure(PasswordHasher.Cost.DEFAULT);
    }
  }

  /** A cost below OWASP's minimum stops the server from starting rather than weakening new hashes. */
  @Test
  public void aCostBelowTheMinimumStopsStartup() {
    try {
      OidcTestSupport.app(new FakeAuthleteApi(), Map.of("lattice.login.argon2.memory-kib", 4_096)).injector().instanceOf(LoginService.class);
      throw new AssertionError("started with 4 MiB and 2 passes");
    } catch (RuntimeException e) {
      assertTrue(String.valueOf(e.getMessage()), String.valueOf(e.getMessage()).contains("below OWASP"));
    } finally {
      PasswordHasher.configure(PasswordHasher.Cost.DEFAULT);
    }
  }
}

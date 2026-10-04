package com.lattice.oidc.security;

import static org.junit.Assert.assertEquals;

import com.lattice.oidc.OidcTestSupport;
import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.UserStore;
import java.util.Map;
import org.junit.Test;
import play.Application;
import play.test.Helpers;

public class LoginServiceTest {

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
}

package com.lattice.oidc.security;

import static org.junit.Assert.assertEquals;

import com.lattice.oidc.OidcTestSupport;
import com.lattice.oidc.client.FakeAuthleteApi;
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
}

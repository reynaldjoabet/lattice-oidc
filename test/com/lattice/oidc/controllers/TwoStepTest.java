package com.lattice.oidc.controllers;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.get;
import static com.lattice.oidc.OidcTestSupport.post;
import static com.lattice.oidc.OidcTestSupport.route;
import static com.lattice.oidc.OidcTestSupport.withCsrf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static play.test.Helpers.contentAsString;

import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.security.SecondFactors;
import com.lattice.oidc.security.Totp;
import com.lattice.oidc.security.TotpCodes;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.Application;
import play.mvc.Result;
import play.test.Helpers;

/** Two-step verification: authenticator apps (TOTP) and recovery codes. */
public class TwoStepTest {

  private static final Pattern SECOND_FACTOR_ID = Pattern.compile("name=\"id\" value=\"([^\"]+)\"");

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private Application app;

  @Before
  public void start() {
    app = app(fake);
    Helpers.start(app);
  }

  @After
  public void stop() {
    Helpers.stop(app);
  }

  /** Enrolls john's authenticator app directly; returns its secret. */
  private String enrollJohn() {
    SecondFactors secondFactors = app.injector().instanceOf(SecondFactors.class);
    String secret = Totp.newSecret();
    // A code from the previous step, so the current one is still unused.
    String code = TotpCodes.at(secret, Totp.step(Instant.now()) - 1);
    assertTrue(secondFactors.finishEnrollment("1001", secret, code));
    return secret;
  }

  private Result passwordSignIn() {
    return route(app, withCsrf(post("/account/login", Map.of("loginId", "john", "password", "john", "next", "account"))));
  }

  private Result submitCode(Result challenge, Map<String, String> fields) {
    Matcher id = SECOND_FACTOR_ID.matcher(contentAsString(challenge));
    assertTrue("the code page carries the pending sign-in", id.find());
    Map<String, String> form = new HashMap<>(fields);
    form.put("id", id.group(1));
    return route(app, withCsrf(post("/sign-in/code", form)).session(challenge.session().data()));
  }

  private boolean signedIn(Map<String, String> session) {
    return contentAsString(route(app, get("/account").session(session))).contains("John Flibble Smith");
  }

  @Test
  public void codesMatchTheRfcTestVector() {
    // RFC 6238 appendix B: the ASCII secret "12345678901234567890" at T = 59 s gives 94287082,
    // whose last six digits are what a 6-digit app shows.
    String secret = TotpCodes.base32("12345678901234567890".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    assertEquals("287082", TotpCodes.at(secret, 59 / 30));
  }

  @Test
  public void aPasswordSignInAsksForTheCodeAndThenSignsIn() {
    String secret = enrollJohn();
    Result challenge = passwordSignIn();
    assertEquals(200, challenge.status());
    assertTrue(contentAsString(challenge).contains("Enter the code"));
    assertFalse("no session before the code", challenge.session().get("session_id").isPresent());

    Result wrong = submitCode(challenge, Map.of("code", "000000"));
    assertEquals(401, wrong.status());

    String code = TotpCodes.at(secret, Totp.step(Instant.now()));
    Result done = submitCode(challenge, Map.of("code", code));
    assertEquals(303, done.status());
    assertEquals("/account", done.redirectLocation().orElse(null));
    assertEquals("the session records the second factor", "mfa", done.session().get("acr").orElse(null));
    assertTrue(signedIn(done.session().data()));

    Result replay = passwordSignIn();
    assertEquals("the same code can't be used twice", 401, submitCode(replay, Map.of("code", code)).status());
  }

  @Test
  public void aRecoveryCodeWorksOnce() {
    enrollJohn();
    List<String> codes = app.injector().instanceOf(SecondFactors.class).newRecoveryCodes("1001");
    Result first = submitCode(passwordSignIn(), Map.of("recoveryCode", codes.get(0).toLowerCase()));
    assertEquals("recovery codes are case-insensitive", 303, first.status());
    assertEquals(9, app.injector().instanceOf(SecondFactors.class).remainingRecoveryCodes("1001"));
    assertEquals(401, submitCode(passwordSignIn(), Map.of("recoveryCode", codes.get(0))).status());
  }

  @Test
  public void tooManyWrongCodesEndTheSignIn() {
    enrollJohn();
    Result challenge = passwordSignIn();
    for (int attempt = 0; attempt < 5; attempt++) {
      submitCode(challenge, Map.of("code", "000000"));
    }
    assertEquals(429, submitCode(challenge, Map.of("code", "000000")).status());
  }

  @Test
  public void settingUpAnAppThroughThePages() {
    Map<String, String> session = passwordSignIn().session().data();
    Result setup = route(app, get("/account/two-step").session(session));
    assertEquals(200, setup.status());
    assertEquals("no-store", setup.header("Cache-Control").orElse(null));
    Matcher key = Pattern.compile("class=\"mono key\">([A-Z2-7]+)<").matcher(contentAsString(setup));
    assertTrue("the key is shown for manual entry", key.find());

    Map<String, String> form = Map.of("code", TotpCodes.at(key.group(1), Totp.step(Instant.now())), "next", "account");
    Result confirmed = route(app, withCsrf(post("/account/two-step", form)).session(setup.session().data()));
    assertEquals(200, confirmed.status());
    assertTrue(contentAsString(confirmed).contains("Save your recovery codes"));
    assertTrue(contentAsString(route(app, get("/account").session(session))).contains("On: password sign-ins also ask for a code"));
  }

  @Test
  public void removingTheAppNeedsThePassword() {
    enrollJohn();
    Result done = submitCode(passwordSignIn(), Map.of("recoveryCode", app.injector().instanceOf(SecondFactors.class).newRecoveryCodes("1001").get(0)));
    Map<String, String> session = done.session().data();
    assertEquals(401, route(app, withCsrf(post("/account/two-step/remove", Map.of("password", "wrong"))).session(session)).status());
    assertEquals(303, route(app, withCsrf(post("/account/two-step/remove", Map.of("password", "john"))).session(session)).status());
    assertFalse(app.injector().instanceOf(SecondFactors.class).enrolled("1001"));
  }
}

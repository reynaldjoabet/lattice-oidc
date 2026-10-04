package com.lattice.oidc.controllers;

import static com.lattice.oidc.OidcTestSupport.get;
import static com.lattice.oidc.OidcTestSupport.post;
import static com.lattice.oidc.OidcTestSupport.route;
import static com.lattice.oidc.OidcTestSupport.withCsrf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static play.inject.Bindings.bind;
import static play.test.Helpers.contentAsString;

import com.authlete.common.api.AuthleteApi;
import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.common.Mailer;
import com.lattice.oidc.security.LoginService;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.Application;
import play.inject.guice.GuiceApplicationBuilder;
import play.mvc.Result;
import play.test.Helpers;

/** Forgotten password: the reset link by email, its rules, and choosing a new password. */
public class AccountRecoveryTest {

  private static final Pattern TOKEN = Pattern.compile("token=([A-Za-z0-9_-]+)");
  private static final String NEW_PASSWORD = "correct horse battery";

  private record Mail(String to, String subject, String text) {}

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private final List<Mail> sent = new CopyOnWriteArrayList<>();
  private Application app;

  @Before
  public void start() {
    fake.answer("nativeSsoLogout", args -> null);
    app =
        new GuiceApplicationBuilder()
            .overrides(
                bind(AuthleteApi.class).toInstance(fake.api()),
                bind(Mailer.class).toInstance((to, subject, text) -> sent.add(new Mail(to, subject, text))))
            .build();
    Helpers.start(app);
  }

  @After
  public void stop() {
    Helpers.stop(app);
  }

  private Result requestLink(String identifier) {
    return route(app, withCsrf(post("/account/recover", Map.of("identifier", identifier, "next", "account"))));
  }

  private String token() {
    Matcher matcher = TOKEN.matcher(sent.get(sent.size() - 1).text());
    assertTrue(matcher.find());
    return matcher.group(1);
  }

  private Result reset(String token, String password, String confirmation, boolean signOutEverywhere) {
    Map<String, String> form =
        signOutEverywhere
            ? Map.of("token", token, "password", password, "confirmation", confirmation, "signOutEverywhere", "true")
            : Map.of("token", token, "password", password, "confirmation", confirmation);
    return route(app, withCsrf(post("/account/reset", form)));
  }

  @Test
  public void theAnswerIsTheSameWhetherOrNotTheAccountExists() {
    Result known = requestLink("john");
    Result unknown = requestLink("nobody@example.com");
    assertEquals(200, known.status());
    assertEquals(200, unknown.status());
    assertTrue(contentAsString(known).contains("If an account matches what you entered"));
    assertEquals(
        contentAsString(known).replaceAll("(value|content)=\"[^\"]*\"", ""),
        contentAsString(unknown).replaceAll("(value|content)=\"[^\"]*\"", ""));
    assertEquals("only the real account gets an email", 1, sent.size());
    assertEquals("john@example.com", sent.get(0).to());
  }

  @Test
  public void emailAddressesWorkAsWellAsLoginIds() {
    requestLink("john@example.com");
    assertEquals(1, sent.size());
  }

  @Test
  public void linksAreRateLimitedPerAccount() {
    for (int attempt = 0; attempt < 5; attempt++) {
      assertEquals(200, requestLink("john").status());
    }
    assertEquals("lattice.recovery.max-requests", 3, sent.size());
  }

  @Test
  public void resetPagesAreNeverCachedOrSentAsReferrer() {
    requestLink("john");
    Result form = route(app, get("/account/reset?token=" + token()));
    assertEquals(200, form.status());
    assertEquals("no-store", form.header("Cache-Control").orElse(null));
    assertEquals("no-referrer", form.header("Referrer-Policy").orElse(null));
    assertTrue(contentAsString(form).contains("Choose a new password"));
  }

  @Test
  public void weakOrMismatchedPasswordsAreRefused() {
    requestLink("john");
    String token = token();
    Result tooShort = reset(token, "short", "short", true);
    assertEquals(400, tooShort.status());
    assertTrue(contentAsString(tooShort).contains("at least 12 characters"));

    Result common = reset(token, "password1234", "password1234", true);
    assertEquals(400, common.status());
    assertTrue(contentAsString(common).contains("less common"));

    Result mismatch = reset(token, NEW_PASSWORD, NEW_PASSWORD + "!", true);
    assertEquals(400, mismatch.status());
    assertTrue(contentAsString(mismatch).contains("don&#x27;t match") || contentAsString(mismatch).contains("don't match"));
  }

  @Test
  public void aGoodPasswordReplacesTheOldOneAndTheLinkWorksOnce() {
    requestLink("john");
    String token = token();
    Result done = reset(token, NEW_PASSWORD, NEW_PASSWORD, false);
    assertEquals(200, done.status());
    assertTrue(contentAsString(done).contains("Password changed"));

    LoginService login = app.injector().instanceOf(LoginService.class);
    assertEquals(LoginService.Outcome.INVALID_CREDENTIALS, login.authenticate("john", "john").outcome());
    assertEquals(LoginService.Outcome.SUCCESS, login.authenticate("john", NEW_PASSWORD).outcome());

    Result again = route(app, get("/account/reset?token=" + token));
    assertEquals(400, again.status());
    assertTrue(contentAsString(again).contains("This link has expired"));
  }

  @Test
  public void onlyTheNewestLinkWorks() {
    requestLink("john");
    String first = token();
    requestLink("john");
    assertEquals(400, route(app, get("/account/reset?token=" + first)).status());
    assertEquals(200, route(app, get("/account/reset?token=" + token())).status());
  }

  @Test
  public void resettingSignsOutEverywhereByDefault() {
    Result signedIn =
        route(app, withCsrf(post("/account/login", Map.of("loginId", "john", "password", "john", "next", "account"))));
    Map<String, String> session = signedIn.session().data();
    assertTrue(contentAsString(route(app, get("/account").session(session))).contains("John Flibble Smith"));

    requestLink("john");
    reset(token(), NEW_PASSWORD, NEW_PASSWORD, true);

    String after = contentAsString(route(app, get("/account").session(session)));
    assertFalse(after.contains("John Flibble Smith"));
    assertTrue(after.contains("to manage your account"));
  }
}

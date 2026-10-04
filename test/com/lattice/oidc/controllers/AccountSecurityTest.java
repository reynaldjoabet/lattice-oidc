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
import com.lattice.oidc.security.LoginService;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.Application;
import play.mvc.Result;
import play.test.Helpers;

/** Where you're signed in, new sign-in alerts, signing out other sessions and changing the password. */
public class AccountSecurityTest {

  private static final Pattern ALERT = Pattern.compile("/account/alerts/([A-Za-z0-9_-]+)");

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private Application app;

  @Before
  public void start() {
    fake.answer("nativeSsoLogout", args -> null);
    app = app(fake);
    Helpers.start(app);
  }

  @After
  public void stop() {
    Helpers.stop(app);
  }

  /** Signs in from a new browser (no cookies); returns its session. */
  private Map<String, String> signInFromNewBrowser(String userAgent) {
    Result login =
        route(
            app,
            withCsrf(post("/account/login", Map.of("loginId", "john", "password", "john", "next", "account")))
                .header("User-Agent", userAgent));
    assertEquals(303, login.status());
    return login.session().data();
  }

  private boolean signedIn(Map<String, String> session) {
    return contentAsString(route(app, get("/account").session(session))).contains("John Flibble Smith");
  }

  private static final String MAC_SAFARI =
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15";
  private static final String WINDOWS_CHROME =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";

  @Test
  public void sessionsPageListsEachBrowserAndMarksThisOne() {
    Map<String, String> mac = signInFromNewBrowser(MAC_SAFARI);
    signInFromNewBrowser(WINDOWS_CHROME);
    Result page = route(app, get("/account/sessions").session(mac));
    assertEquals(200, page.status());
    String html = contentAsString(page);
    assertTrue(html.contains("Safari on macOS"));
    assertTrue(html.contains("Chrome on Windows"));
    assertTrue(html.contains("This browser"));
    assertTrue(html.contains("Sign out everywhere else"));
  }

  @Test
  public void signingOutAnotherSessionEndsIt() {
    Map<String, String> mac = signInFromNewBrowser(MAC_SAFARI);
    Map<String, String> windows = signInFromNewBrowser(WINDOWS_CHROME);
    Result ended =
        route(app, withCsrf(post("/account/sessions/" + windows.get("session_id") + "/end", Map.of())).session(mac));
    assertEquals(303, ended.status());
    assertFalse(signedIn(windows));
    assertTrue(signedIn(mac));
  }

  @Test
  public void aSessionCannotEndAnotherAccountsSession() {
    Map<String, String> john = signInFromNewBrowser(MAC_SAFARI);
    Result jane =
        route(app, withCsrf(post("/account/login", Map.of("loginId", "jane", "password", "jane", "next", "account"))));
    Map<String, String> janeSession = jane.session().data();
    route(app, withCsrf(post("/account/sessions/" + janeSession.get("session_id") + "/end", Map.of())).session(john));
    assertTrue(contentAsString(route(app, get("/account").session(janeSession))).contains("Jane"));
  }

  @Test
  public void aSignInFromANewBrowserRaisesAnAlertElsewhere() {
    Map<String, String> mac = signInFromNewBrowser(MAC_SAFARI);
    Map<String, String> windows = signInFromNewBrowser(WINDOWS_CHROME);
    String macPage = contentAsString(route(app, get("/account").session(mac)));
    assertTrue(macPage.contains("New sign-in to your account"));
    assertTrue(macPage.contains("Chrome on Windows"));
    String windowsPage = contentAsString(route(app, get("/account").session(windows)));
    assertFalse("the new session itself isn't asked", windowsPage.contains("New sign-in to your account"));
  }

  @Test
  public void answeringNoEndsThatSessionAndAsksForANewPassword() {
    Map<String, String> mac = signInFromNewBrowser(MAC_SAFARI);
    Map<String, String> windows = signInFromNewBrowser(WINDOWS_CHROME);
    Matcher alert = ALERT.matcher(contentAsString(route(app, get("/account").session(mac))));
    assertTrue(alert.find());
    Result answered =
        route(app, withCsrf(post("/account/alerts/" + alert.group(1), Map.of("answer", "no"))).session(mac));
    assertEquals(303, answered.status());
    assertEquals("/account/password", answered.redirectLocation().orElse(null));
    assertFalse(signedIn(windows));
    assertFalse(contentAsString(route(app, get("/account").session(mac))).contains("New sign-in to your account"));
  }

  @Test
  public void answeringYesKeepsTheSession() {
    Map<String, String> mac = signInFromNewBrowser(MAC_SAFARI);
    Map<String, String> windows = signInFromNewBrowser(WINDOWS_CHROME);
    Matcher alert = ALERT.matcher(contentAsString(route(app, get("/account").session(mac))));
    assertTrue(alert.find());
    route(app, withCsrf(post("/account/alerts/" + alert.group(1), Map.of("answer", "yes"))).session(mac));
    assertTrue(signedIn(windows));
    assertFalse(contentAsString(route(app, get("/account").session(mac))).contains("New sign-in to your account"));
  }

  @Test
  public void signingOutOthersKeepsThisSession() {
    Map<String, String> mac = signInFromNewBrowser(MAC_SAFARI);
    Map<String, String> windows = signInFromNewBrowser(WINDOWS_CHROME);
    Result confirm = route(app, get("/account/sessions/others").session(mac));
    assertTrue(contentAsString(confirm).contains("Sign out of 1 other session?"));
    Result done = route(app, withCsrf(post("/account/sessions/others", Map.of())).session(mac));
    assertEquals(303, done.status());
    assertFalse(signedIn(windows));
    assertTrue(signedIn(mac));
  }

  @Test
  public void changingThePasswordNeedsTheCurrentOne() {
    Map<String, String> mac = signInFromNewBrowser(MAC_SAFARI);
    Map<String, String> windows = signInFromNewBrowser(WINDOWS_CHROME);
    String strong = "correct horse battery";
    Result wrong =
        route(
            app,
            withCsrf(post("/account/password", Map.of("current", "nope", "password", strong, "confirmation", strong)))
                .session(mac));
    assertEquals(401, wrong.status());

    Result changed =
        route(
            app,
            withCsrf(
                    post(
                        "/account/password",
                        Map.of("current", "john", "password", strong, "confirmation", strong, "signOutEverywhere", "true")))
                .session(mac));
    assertEquals(200, changed.status());
    assertTrue(contentAsString(changed).contains("Password changed"));
    LoginService login = app.injector().instanceOf(LoginService.class);
    assertEquals(LoginService.Outcome.SUCCESS, login.authenticate("john", strong).outcome());
    assertFalse("other sessions are signed out", signedIn(windows));
    assertTrue("this one stays", signedIn(mac));
  }

  @Test
  public void anIdleSessionEnds() throws InterruptedException {
    Helpers.stop(app);
    app = app(fake, Map.of("lattice.session.idle-timeout", "1s"));
    Helpers.start(app);
    Map<String, String> mac = signInFromNewBrowser(MAC_SAFARI);
    assertTrue(signedIn(mac));
    Thread.sleep(1_200);
    assertFalse("idle longer than lattice.session.idle-timeout", signedIn(mac));
  }
}

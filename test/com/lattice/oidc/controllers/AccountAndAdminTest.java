package com.lattice.oidc.controllers;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.get;
import static com.lattice.oidc.OidcTestSupport.post;
import static com.lattice.oidc.OidcTestSupport.route;
import static com.lattice.oidc.OidcTestSupport.withCsrf;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static play.test.Helpers.contentAsString;

import com.authlete.common.dto.AuthorizedClientListResponse;
import com.authlete.common.dto.ClientAuthorizationGetListRequest;
import com.authlete.common.dto.Client;
import com.lattice.oidc.client.FakeAuthleteApi;
import java.util.List;
import java.util.Map;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.Application;
import play.mvc.Result;
import play.test.Helpers;

/** The account page (apps with access, sign-in methods), its sign-in, and the operator console. */
public class AccountAndAdminTest {

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private Application app;

  @Before
  public void start() {
    Client notes = new Client();
    notes.setClientId(42L);
    notes.setClientName("Acme Notes");
    fake.answer(
            "getClientAuthorizationList",
            args -> {
              AuthorizedClientListResponse r = new AuthorizedClientListResponse();
              r.setClients(new Client[] {notes});
              return r;
            })
        .answer("deleteClientAuthorization", args -> null)
        .answer("getServiceConfiguration", args -> "{\"issuer\":\"https://lattice.example\"}")
        .answer("getServiceJwks", args -> "{\"keys\":[]}");
    app = app(fake, Map.of("lattice.admin.login-ids", List.of("john")));
    Helpers.start(app);
  }

  @After
  public void stop() {
    Helpers.stop(app);
  }

  private Result signIn(String loginId, String next) {
    return route(
        app, withCsrf(post("/account/login", Map.of("loginId", loginId, "password", loginId, "next", next))));
  }

  @Test
  public void accountPageAsksAnonymousVisitorsToSignIn() {
    Result r = route(app, get("/account"));
    assertEquals(200, r.status());
    assertTrue(contentAsString(r).contains("to manage your account"));
    assertEquals(0, fake.count("getClientAuthorizationList"));
  }

  @Test
  public void signedInUserSeesAppsAndSignInMethods() {
    Result login = signIn("john", "account");
    assertEquals(303, login.status());
    assertEquals("/account", login.redirectLocation().orElse(null));

    Result page = route(app, get("/account").session(login.session().data()));
    assertEquals(200, page.status());
    String html = contentAsString(page);
    assertTrue(html.contains("John Flibble Smith"));
    assertTrue(html.contains("Acme Notes"));
    assertTrue(html.contains("login ID john"));
    ClientAuthorizationGetListRequest listed = fake.lastRequest("getClientAuthorizationList");
    assertEquals("1001", listed.getSubject());
  }

  @Test
  public void removingAnAppDeletesItsAuthorizationForThisUser() {
    Result login = signIn("john", "account");
    Result r =
        route(app, withCsrf(post("/account/apps/42/remove", Map.of())).session(login.session().data()));
    assertEquals(303, r.status());
    assertArrayEquals(new Object[] {42L, "1001"}, fake.lastArgs.get("deleteClientAuthorization"));
  }

  @Test
  public void removingWithoutASessionDoesNothing() {
    Result r = route(app, withCsrf(post("/account/apps/42/remove", Map.of())));
    assertEquals(400, r.status());
    assertEquals(0, fake.count("deleteClientAuthorization"));
  }

  @Test
  public void signInOnlyContinuesToKnownPages() {
    Result r = signIn("john", "https://evil.example/");
    assertEquals(303, r.status());
    assertEquals("/account", r.redirectLocation().orElse(null));
  }

  @Test
  public void wrongPasswordStaysOnTheSignInPage() {
    Result r =
        route(app, withCsrf(post("/account/login", Map.of("loginId", "john", "password", "nope", "next", "account"))));
    assertEquals(401, r.status());
    assertTrue(contentAsString(r).contains("Invalid login ID or password."));
  }

  @Test
  public void consoleIsOnlyForConfiguredAdmins() {
    Result anonymous = route(app, get("/admin"));
    assertEquals(200, anonymous.status());
    assertTrue(contentAsString(anonymous).contains("to open the operator console"));

    Result jane = signIn("jane", "admin");
    assertEquals(403, route(app, get("/admin").session(jane.session().data())).status());

    Result john = signIn("john", "admin");
    assertEquals("/admin", john.redirectLocation().orElse(null));
    Result console = route(app, get("/admin").session(john.session().data()));
    assertEquals(200, console.status());
    String html = contentAsString(console);
    assertTrue(html.contains("Connected"));
    assertTrue("the storage panel lists sessions", html.contains(">sessions<"));
    assertTrue(html.contains("<h2>Storage</h2>"));
    assertTrue(html.contains("<h2>Two-step verification</h2>"));
    assertFalse("no directory configured", html.contains("<h2>LDAP directory</h2>"));
    assertTrue("recent audit events are listed", html.contains("LOGIN_SUCCEEDED"));
    assertEquals("no-store", console.header("Cache-Control").orElse(null));
  }

  @Test
  public void accountPageLinksAdminsToTheConsole() {
    Result john = signIn("john", "account");
    assertTrue(contentAsString(route(app, get("/account").session(john.session().data()))).contains("Operator console"));
    Result jane = signIn("jane", "account");
    assertTrue(!contentAsString(route(app, get("/account").session(jane.session().data()))).contains("Operator console"));
  }
}

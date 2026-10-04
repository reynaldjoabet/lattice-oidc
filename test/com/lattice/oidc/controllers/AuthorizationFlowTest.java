package com.lattice.oidc.controllers;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.get;
import static com.lattice.oidc.OidcTestSupport.post;
import static com.lattice.oidc.OidcTestSupport.route;
import static com.lattice.oidc.OidcTestSupport.withCsrf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static play.test.Helpers.contentAsString;

import com.authlete.common.dto.AuthorizationFailRequest;
import com.authlete.common.dto.AuthorizationFailResponse;
import com.authlete.common.dto.AuthorizationIssueRequest;
import com.authlete.common.dto.AuthorizationIssueResponse;
import com.authlete.common.dto.AuthorizationRequest;
import com.authlete.common.dto.AuthorizationResponse;
import com.authlete.common.dto.Client;
import com.authlete.common.dto.Scope;
import com.authlete.common.dto.Service;
import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.models.Consent;
import com.lattice.oidc.stores.ConsentStore;
import java.util.List;
import java.util.Map;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.Application;
import play.mvc.Http;
import play.mvc.Result;
import play.test.Helpers;

public class AuthorizationFlowTest {

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private Application app;

  @Before
  public void start() {
    fake.answer("authorization", args -> interaction("ticket-1", null))
        .answer("authorizationIssue", args -> issued("https://client.example/cb?code=abc"))
        .answer(
            "authorizationFail",
            args -> {
              AuthorizationFailResponse r = new AuthorizationFailResponse();
              r.setAction(AuthorizationFailResponse.Action.LOCATION);
              r.setResponseContent("https://client.example/cb?error=access_denied");
              return r;
            });
    // No "create a passkey" offer between sign-in and consent here (PasskeyFlowTest covers it).
    app = app(fake, Map.of("lattice.passkeys.offer-interval", "0s"));
    Helpers.start(app);
  }

  @After
  public void stop() {
    Helpers.stop(app);
  }

  static AuthorizationResponse interaction(String ticket, AuthorizationResponse.Action action) {
    AuthorizationResponse r = new AuthorizationResponse();
    r.setAction(action == null ? AuthorizationResponse.Action.INTERACTION : action);
    r.setTicket(ticket);
    Client client = new Client();
    client.setClientId(42L);
    client.setClientName("Demo <App>");
    r.setClient(client);
    Service service = new Service();
    service.setServiceName("Lattice");
    r.setService(service);
    r.setScopes(new Scope[] {new Scope().setName("openid"), new Scope().setName("profile")});
    r.setClaims(new String[] {"name", "email"});
    return r;
  }

  static AuthorizationIssueResponse issued(String location) {
    AuthorizationIssueResponse r = new AuthorizationIssueResponse();
    r.setAction(AuthorizationIssueResponse.Action.LOCATION);
    r.setResponseContent(location);
    return r;
  }

  private Result consentPage() {
    Result page =
        route(app, withCsrf(get("/api/authorization?response_type=code&client_id=42&scope=openid")));
    assertEquals(200, page.status());
    return page;
  }

  private static Http.RequestBuilder decision(Result page, Map<String, String> form) {
    return withCsrf(post("/api/authorization/decision", form)).session(page.session().data());
  }

  @Test
  public void rendersConsentWithEscapedClientNameAndPassesRawQuery() {
    Result page = consentPage();
    String html = contentAsString(page);
    assertTrue(html.contains("Demo &lt;App&gt;"));
    assertTrue(html.contains("value=\"ticket-1\""));
    assertEquals("no-store", page.header("Cache-Control").orElse(null));
    AuthorizationRequest sent = fake.lastRequest("authorization");
    assertEquals("response_type=code&client_id=42&scope=openid", sent.getParameters());
  }

  @Test
  public void loginAndApproveIssuesCodeForUserWithClaimsAndSession() {
    Result page = consentPage();
    Result r =
        route(
            app,
            decision(
                page,
                Map.of("ticket", "ticket-1", "loginId", "john", "password", "john", "authorized", "true")));
    assertEquals(302, r.status());
    assertEquals("https://client.example/cb?code=abc", r.redirectLocation().orElse(null));

    AuthorizationIssueRequest issue = fake.lastRequest("authorizationIssue");
    assertEquals("1001", issue.getSubject());
    assertNotNull("the session ID must be bound for logout/native SSO", issue.getSessionId());
    assertTrue(issue.getClaims().contains("John Flibble Smith"));
    assertEquals(issue.getSessionId(), r.session().get("session_id").orElse(null));

    // The ticket is single-use.
    Result replay =
        route(app, decision(page, Map.of("ticket", "ticket-1", "authorized", "true")));
    assertEquals(400, replay.status());
  }

  @Test
  public void wrongPasswordRerendersWithoutIssuing() {
    Result page = consentPage();
    Result r =
        route(
            app,
            decision(
                page,
                Map.of("ticket", "ticket-1", "loginId", "john", "password", "nope", "authorized", "true")));
    assertEquals(401, r.status());
    assertTrue(contentAsString(r).contains("Invalid login ID or password."));
    assertEquals(0, fake.count("authorizationIssue"));
  }

  @Test
  public void denyFailsWithDenied() {
    Result page = consentPage();
    Result r = route(app, decision(page, Map.of("ticket", "ticket-1", "denied", "true")));
    assertEquals(302, r.status());
    AuthorizationFailRequest fail = fake.lastRequest("authorizationFail");
    assertEquals(AuthorizationFailRequest.Reason.DENIED, fail.getReason());
  }

  @Test
  public void decisionFromAnotherBrowserIsRejected() {
    consentPage();
    Result r =
        route(
            app,
            withCsrf(
                post(
                    "/api/authorization/decision",
                    Map.of("ticket", "ticket-1", "loginId", "john", "password", "john", "authorized", "true"))));
    assertEquals(400, r.status());
    assertEquals(0, fake.count("authorizationIssue"));
  }

  @Test
  public void promptNoneWithoutSessionFailsNotLoggedIn() {
    fake.answer(
        "authorization", args -> interaction("t-none", AuthorizationResponse.Action.NO_INTERACTION));
    Result r = route(app, get("/api/authorization?prompt=none"));
    assertEquals(302, r.status());
    AuthorizationFailRequest fail = fake.lastRequest("authorizationFail");
    assertEquals(AuthorizationFailRequest.Reason.NOT_LOGGED_IN, fail.getReason());
  }

  @Test
  public void authleteErrorsArePassedThrough() {
    fake.answer(
        "authorization",
        args -> {
          AuthorizationResponse r = new AuthorizationResponse();
          r.setAction(AuthorizationResponse.Action.BAD_REQUEST);
          r.setResponseContent("{\"error\":\"invalid_request\"}");
          return r;
        });
    Result r = route(app, get("/api/authorization"));
    assertEquals(400, r.status());
    assertTrue(contentAsString(r).contains("invalid_request"));
  }

  /** Step 1 of the two-step flow: sign in on the sign-in page; returns the consent page. */
  private Result signIn(Result page, String password) {
    return route(
        app, decision(page, Map.of("ticket", "ticket-1", "loginId", "john", "password", password, "login", "true")));
  }

  @Test
  public void signInThenConsentIssuesForTheSignedInUser() {
    Result page = consentPage();
    String identifierHtml = contentAsString(page);
    assertTrue("step 1 asks for the email or login ID", identifierHtml.contains("name=\"identifier\""));
    assertTrue("step 1 does not ask for the password yet", !identifierHtml.contains("name=\"password\""));
    assertTrue("step 1 does not ask for consent yet", !identifierHtml.contains("name=\"authorized\""));

    Result passwordStep =
        route(app, decision(page, Map.of("ticket", "ticket-1", "identifier", "john", "identify", "true")));
    assertEquals(200, passwordStep.status());
    String passwordHtml = contentAsString(passwordStep);
    assertTrue("step 2 asks for the password", passwordHtml.contains("name=\"password\""));
    assertTrue("step 2 shows who is signing in", passwordHtml.contains("<strong>john</strong>"));

    Result consent = signIn(page, "john");
    assertEquals(200, consent.status());
    String html = contentAsString(consent);
    assertTrue(html.contains("Signed in as"));
    assertTrue(html.contains("name=\"authorized\""));
    assertNotNull("signing in starts a session", consent.session().get("session_id").orElse(null));
    assertEquals(0, fake.count("authorizationIssue"));

    Result issued =
        route(
            app,
            withCsrf(post("/api/authorization/decision", Map.of("ticket", "ticket-1", "authorized", "true")))
                .session(consent.session().data()));
    assertEquals(302, issued.status());
    AuthorizationIssueRequest issue = fake.lastRequest("authorizationIssue");
    assertEquals("1001", issue.getSubject());
  }

  @Test
  public void failedSignInStaysOnTheSignInStep() {
    Result r = signIn(consentPage(), "nope");
    assertEquals(401, r.status());
    String html = contentAsString(r);
    assertTrue(html.contains("Invalid login ID or password."));
    assertTrue(html.contains("name=\"password\""));
    assertTrue(!html.contains("Signed in as"));
  }

  @Test
  public void consentPageUsesPlainLanguage() {
    String html = contentAsString(signIn(consentPage(), "john"));
    assertTrue(html.contains("Sign you in with your account"));
    assertTrue(html.contains("Your basic profile"));
    assertTrue(html.contains("Full name"));
    assertTrue(html.contains("Email address"));
    assertTrue("protocol jargon stays out of the main text", !html.contains("prompt=login"));
  }

  @Test
  public void returningUserCanSwitchToAnotherAccount() {
    // First authorization: log in as john.
    Result page = consentPage();
    Result first =
        route(
            app,
            decision(
                page,
                Map.of("ticket", "ticket-1", "loginId", "john", "password", "john", "authorized", "true")));
    Map<String, String> session = first.session().data();

    // Second authorization in the same browser: john's session is offered.
    fake.answer("authorization", args -> interaction("ticket-2", null));
    Result second =
        route(app, withCsrf(get("/api/authorization?client_id=42")).session(session));
    assertTrue(contentAsString(second).contains("Signed in as"));

    // "Use a different account" shows the login form instead.
    Result switched =
        route(
            app,
            withCsrf(post("/api/authorization/decision", Map.of("ticket", "ticket-2", "switchAccount", "true")))
                .session(session));
    assertEquals(200, switched.status());
    String html = contentAsString(switched);
    assertTrue(html.contains("name=\"identifier\""));
    assertTrue(!html.contains("Signed in as"));

    // Approving without credentials now requires a login.
    Result noLogin =
        route(
            app,
            withCsrf(post("/api/authorization/decision", Map.of("ticket", "ticket-2", "authorized", "true")))
                .session(session));
    assertEquals(401, noLogin.status());

    // Logging in as jane issues the code for jane.
    Result jane =
        route(
            app,
            withCsrf(
                    post(
                        "/api/authorization/decision",
                        Map.of("ticket", "ticket-2", "loginId", "jane", "password", "jane", "authorized", "true")))
                .session(session));
    assertEquals(302, jane.status());
    AuthorizationIssueRequest issue = fake.lastRequest("authorizationIssue");
    assertEquals("1002", issue.getSubject());
  }

  @Test
  public void openBankingConsentShowsTheAccountPermissionsAndExpiry() {
    Consent consent =
        app.injector()
            .instanceOf(ConsentStore.class)
            .create(List.of("ACCOUNTS_READ", "ACCOUNTS_BALANCES_READ"), "2030-01-01T00:00:00Z", 42L);
    fake.answer(
        "authorization",
        args -> {
          AuthorizationResponse r = interaction("ticket-1", null);
          r.setScopes(
              new Scope[] {
                new Scope().setName("openid"), new Scope().setName("consent:" + consent.consentId())
              });
          return r;
        });
    String html = contentAsString(signIn(consentPage(), "john"));
    assertTrue(html.contains("Share your account data with"));
    assertTrue(html.contains("Account details"));
    assertTrue(html.contains("ACCOUNTS_BALANCES_READ"));
    assertTrue(html.contains("1 Jan 2030"));
    assertTrue(html.contains("Confirm sharing"));
  }
}

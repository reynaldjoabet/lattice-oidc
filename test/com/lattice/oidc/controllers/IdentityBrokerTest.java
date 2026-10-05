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
import com.authlete.common.dto.AuthorizationIssueRequest;
import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.handlers.FakeUpstreamProvider;
import com.lattice.oidc.security.AuditService;
import java.net.URI;
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

/**
 * Identity brokering: sign-in at an upstream OpenID Provider during an authorization request. The
 * upstream is a real local HTTP server, so discovery, ID token signature/nonce validation and the
 * UserInfo subject check all run for real.
 */
public class IdentityBrokerTest {

  private static final String CALLBACK = "http://localhost/api/federation/callback/upstream";

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private final List<Map<String, Object>> audit = new CopyOnWriteArrayList<>();
  private FakeUpstreamProvider upstream;
  private Application app;

  @Before
  public void start() throws Exception {
    upstream = new FakeUpstreamProvider();
    fake.answer("authorization", args -> AuthorizationFlowTest.interaction("ticket-1", null))
        .answer("authorizationIssue", args -> AuthorizationFlowTest.issued("https://client.example/cb?code=abc"));
    app =
        new GuiceApplicationBuilder()
            .configure(
                "lattice.identity-providers.file",
                upstream.configFile("upstream", CALLBACK, List.of("partner.example")).toString())
            .overrides(
                bind(AuthleteApi.class).toInstance(fake.api()),
                bind(AuditService.Sink.class).toInstance(audit::add))
            .build();
    Helpers.start(app);
  }

  @After
  public void stop() {
    Helpers.stop(app);
    upstream.close();
  }

  private Result consentPage() {
    Result page = route(app, withCsrf(get("/api/authorization?response_type=code&client_id=42")));
    assertEquals(200, page.status());
    return page;
  }

  /** Starts the brokered login; returns the {@code state} sent upstream (and records the nonce). */
  private String initiate(Result page) {
    Result r =
        route(app, get("/api/federation/initiation/upstream?ticket=ticket-1").session(page.session().data()));
    assertEquals(302, r.status());
    URI location = URI.create(r.redirectLocation().orElseThrow());
    assertTrue(location.toString().startsWith(upstream.issuer + "/authorize"));
    Map<String, String[]> query = Requests.decode(location.getRawQuery());
    assertEquals("S256", Requests.first(query, "code_challenge_method"));
    assertEquals(CALLBACK, Requests.first(query, "redirect_uri"));
    upstream.nonce = Requests.first(query, "nonce");
    return Requests.first(query, "state");
  }

  private Result callback(Result page, String state) {
    return route(
        app,
        get("/api/federation/callback/upstream?code=upstream-code&state=" + state)
            .session(page.session().data()));
  }

  /** Whether the response started a login session ({@code session()} is null when untouched). */
  private static boolean loggedIn(Result r) {
    return r.session() != null && r.session().get("session_id").isPresent();
  }

  private boolean audited(AuditService.Event event) {
    return audit.stream().anyMatch(r -> event.name().equals(String.valueOf(r.get("event"))));
  }

  @Test
  public void consentPageOffersTheProvider() {
    String html = contentAsString(consentPage());
    assertTrue(html.contains("/api/federation/initiation/upstream"));
  }

  @Test
  public void brokeredLoginLogsInTheMappedUserWhoCanThenAuthorize() {
    Result page = consentPage();
    Result back = callback(page, initiate(page));
    assertEquals(200, back.status());
    assertTrue(contentAsString(back).contains("Alice Upstream"));
    assertTrue(loggedIn(back));
    assertTrue(audited(AuditService.Event.BROKERED_LOGIN));
    assertTrue(
        app.injector()
            .instanceOf(com.lattice.oidc.metrics.Metrics.class)
            .scrape()
            .contains("lattice_identity_provider_sign_ins_seconds_count{outcome=\"success\",provider=\"upstream\"} 1"));

    Result decision =
        route(
            app,
            withCsrf(post("/api/authorization/decision", Map.of("ticket", "ticket-1", "authorized", "true")))
                .session(back.session().data()));
    assertEquals(302, decision.status());
    AuthorizationIssueRequest issue = fake.lastRequest("authorizationIssue");
    assertEquals("alice@upstream", issue.getSubject());
  }

  @Test
  public void callbackFromAnotherBrowserIsRejectedBeforeRedeemingTheCode() {
    Result page = consentPage();
    String state = initiate(page);
    Result r = route(app, get("/api/federation/callback/upstream?code=upstream-code&state=" + state));
    assertEquals(400, r.status());
    assertEquals(0, upstream.tokenRequests.get());
  }

  @Test
  public void forgedOrReplayedStateIsRejected() {
    Result page = consentPage();
    String state = initiate(page);
    assertEquals(400, callback(page, "forged").status());

    assertEquals(200, callback(page, state).status());
    assertEquals("state is single-use", 400, callback(page, state).status());
    assertEquals(1, upstream.tokenRequests.get());
  }

  @Test
  public void stateIssuedForOneProviderCannotBeUsedOnAnother() {
    Result page = consentPage();
    String state = initiate(page);
    Result r =
        route(
            app,
            get("/api/federation/callback/other?code=upstream-code&state=" + state)
                .session(page.session().data()));
    assertEquals(400, r.status());
    assertEquals(0, upstream.tokenRequests.get());
  }

  @Test
  public void idTokenForAnotherNonceIsRejected() {
    Result page = consentPage();
    String state = initiate(page);
    upstream.nonce = "replayed-from-another-login";
    Result r = callback(page, state);
    assertEquals(502, r.status());
    assertFalse(loggedIn(r));
    assertTrue(audited(AuditService.Event.BROKERED_LOGIN_FAILED));
    assertTrue(
        app.injector()
            .instanceOf(com.lattice.oidc.metrics.Metrics.class)
            .scrape()
            .contains("lattice_identity_provider_sign_ins_seconds_count{outcome=\"error\",provider=\"upstream\"} 1"));
  }

  @Test
  public void userInfoForAnotherSubjectIsRejected() {
    Result page = consentPage();
    String state = initiate(page);
    upstream.userInfoSubject = "mallory";
    Result r = callback(page, state);
    assertEquals(502, r.status());
    assertFalse(loggedIn(r));
  }

  @Test
  public void unknownProviderAndUnknownTicketAreRejected() {
    Result page = consentPage();
    Result unknownProvider =
        route(app, get("/api/federation/initiation/nope?ticket=ticket-1").session(page.session().data()));
    assertEquals(404, unknownProvider.status());

    Result unknownTicket =
        route(app, get("/api/federation/initiation/upstream?ticket=other").session(page.session().data()));
    assertEquals(400, unknownTicket.status());

    Result otherBrowser = route(app, get("/api/federation/initiation/upstream?ticket=ticket-1"));
    assertEquals(400, otherBrowser.status());
  }

  // --- Linking an upstream sign-in to an existing account with the same email ---

  private static String linkId(Result page) {
    Matcher matcher = Pattern.compile("name=\"linkId\" value=\"([^\"]+)\"").matcher(contentAsString(page));
    assertTrue("the link page is shown", matcher.find());
    return matcher.group(1);
  }

  private Result answer(Result page, String linkId, Map<String, String> choice) {
    Map<String, String> form = new java.util.HashMap<>(choice);
    form.put("linkId", linkId);
    return route(app, withCsrf(post("/api/federation/link", form)).session(page.session().data()));
  }

  private void authorize(Result signedIn) {
    Result r =
        route(
            app,
            withCsrf(post("/api/authorization/decision", Map.of("ticket", "ticket-1", "authorized", "true")))
                .session(signedIn.session().data()));
    assertEquals(302, r.status());
  }

  @Test
  public void matchingEmailAsksToLinkAndThePasswordLinksTheAccounts() {
    upstream.email = "john@example.com";
    Result page = consentPage();
    Result asked = callback(page, initiate(page));
    assertEquals(200, asked.status());
    String html = contentAsString(asked);
    assertTrue(html.contains("You already have an account"));
    assertTrue(html.contains("John Flibble Smith"));
    assertFalse("nobody is signed in before the password check", loggedIn(asked));

    String linkId = linkId(asked);
    Result wrong = answer(page, linkId, Map.of("link", "true", "password", "nope"));
    assertEquals(401, wrong.status());
    assertFalse(loggedIn(wrong));

    Result linked = answer(page, linkId, Map.of("link", "true", "password", "john"));
    assertEquals(200, linked.status());
    assertTrue(contentAsString(linked).contains("Signed in as"));
    assertTrue(audited(AuditService.Event.ACCOUNT_LINKED));
    authorize(linked);
    assertEquals("1001", ((AuthorizationIssueRequest) fake.lastRequest("authorizationIssue")).getSubject());

    // Next time the same upstream identity signs straight in to the linked account, and the app,
    // approved last time, gets its code without the consent page.
    Result again = consentPage();
    Result direct = callback(again, initiate(again));
    assertEquals(303, direct.status());
    assertEquals("/api/authorization/continue?ticket=ticket-1", direct.redirectLocation().orElse(null));
    Result continued = route(app, get(direct.redirectLocation().get()).session(direct.session().data()));
    assertEquals(302, continued.status());
    assertEquals(2, fake.count("authorizationIssue"));
    assertEquals("1001", ((AuthorizationIssueRequest) fake.lastRequest("authorizationIssue")).getSubject());
  }

  @Test
  public void keepingAccountsSeparateUsesTheBrokeredAccount() {
    upstream.email = "john@example.com";
    Result page = consentPage();
    Result asked = callback(page, initiate(page));
    Result separate = answer(page, linkId(asked), Map.of("separate", "true"));
    assertEquals(200, separate.status());
    assertTrue(loggedIn(separate));
    authorize(separate);
    assertEquals("alice@upstream", ((AuthorizationIssueRequest) fake.lastRequest("authorizationIssue")).getSubject());
  }

  @Test
  public void linkAnswerFromAnotherBrowserIsRejected() {
    upstream.email = "john@example.com";
    Result page = consentPage();
    String linkId = linkId(callback(page, initiate(page)));
    Result r =
        route(app, withCsrf(post("/api/federation/link", Map.of("linkId", linkId, "link", "true", "password", "john"))));
    assertEquals(400, r.status());
  }

  @Test
  public void workEmailsGoToTheirOrganisationsProvider() {
    Result page = consentPage();
    Result realm =
        route(
            app,
            withCsrf(
                    post(
                        "/api/authorization/decision",
                        Map.of("ticket", "ticket-1", "identifier", "Ana@Partner.Example", "identify", "true")))
                .session(page.session().data()));
    assertEquals(200, realm.status());
    String html = contentAsString(realm);
    assertTrue(html.contains("Continue with Upstream"));
    assertTrue(html.contains("/api/federation/initiation/upstream?ticket=ticket-1"));
    assertTrue("no password is asked for", !html.contains("name=\"password\""));
  }

  @Test
  public void otherEmailsContinueToThePassword() {
    Result page = consentPage();
    Result password =
        route(
            app,
            withCsrf(
                    post(
                        "/api/authorization/decision",
                        Map.of("ticket", "ticket-1", "identifier", "someone@elsewhere.example", "identify", "true")))
                .session(page.session().data()));
    assertTrue(contentAsString(password).contains("name=\"password\""));
  }

  @Test
  public void requiredActionsComeBeforeConsentAfterABrokeredSignIn() {
    Result first = consentPage();
    callback(first, initiate(first));
    // Flag the provisioned account, then sign in through the provider again.
    var users = app.injector().instanceOf(com.lattice.oidc.stores.UserStore.class);
    var alice = users.bySubject("alice@upstream").orElseThrow();
    Map<String, Object> attributes = new java.util.HashMap<>(alice.attributes());
    attributes.put("requiredActions", List.of("CONFIGURE_PASSKEY"));
    users.save(new com.lattice.oidc.models.User(alice.getSubject(), alice.loginId(), alice.passwordHash(), alice.claims(), attributes, alice.verifiedClaims()));

    Result page = consentPage();
    Result back = callback(page, initiate(page));
    assertEquals(303, back.status());
    assertEquals("/account/actions?next=authz%3Aticket-1", back.redirectLocation().orElse(null));
  }
}

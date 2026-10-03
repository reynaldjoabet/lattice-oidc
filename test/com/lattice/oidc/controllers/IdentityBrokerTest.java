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
                upstream.configFile("upstream", CALLBACK).toString())
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
    return r.session() != null && r.session().get("sid").isPresent();
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
}

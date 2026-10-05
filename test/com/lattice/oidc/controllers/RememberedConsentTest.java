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

import com.authlete.common.dto.AuthorizationFailRequest;
import com.authlete.common.dto.AuthorizationFailResponse;
import com.authlete.common.dto.AuthorizationResponse;
import com.authlete.common.dto.Scope;
import com.authlete.common.types.Prompt;
import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.stores.AuditEventStore;
import java.util.Map;
import java.util.Optional;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.Application;
import play.mvc.Result;
import play.test.Helpers;

/** An approved app isn't asked about again, in any browser, until it asks for more. */
public class RememberedConsentTest {

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private Application app;

  @Before
  public void start() {
    asks(AuthorizationFlowTest.interaction("ticket-1", null));
    fake.answer("authorizationIssue", args -> AuthorizationFlowTest.issued("https://client.example/cb?code=abc"))
        .answer("deleteClientAuthorization", args -> null)
        .answer(
            "authorizationFail",
            args -> {
              AuthorizationFailResponse response = new AuthorizationFailResponse();
              response.setAction(AuthorizationFailResponse.Action.LOCATION);
              response.setResponseContent("https://client.example/cb?error=consent_required");
              return response;
            });
    app = app(fake, Map.of("lattice.passkeys.offer-interval", "0s"));
    Helpers.start(app);
  }

  @After
  public void stop() {
    Helpers.stop(app);
  }

  /** The next authorization request Authlete reports. */
  private void asks(AuthorizationResponse response) {
    fake.answer("authorization", args -> response);
  }

  private Result authorize(Map<String, String> session) {
    return route(app, withCsrf(get("/api/authorization?response_type=code&client_id=42")).session(session));
  }

  /** Signs john in on the consent page and approves; returns the signed-in session. */
  private Map<String, String> approveAsJohn() {
    Result page = authorize(Map.of());
    Result approved =
        route(
            app,
            withCsrf(
                    post(
                        "/api/authorization/decision",
                        Map.of("ticket", "ticket-1", "loginId", "john", "password", "john", "authorized", "true")))
                .session(page.session().data()));
    assertEquals(302, approved.status());
    return approved.session().data();
  }

  private long audited(String event) {
    return app.injector()
        .instanceOf(AuditEventStore.class)
        .search(new AuditEventStore.Query(Optional.of(event), Optional.empty(), Optional.empty(), 100))
        .size();
  }

  @Test
  public void theSameBrowserIsNotAskedAgain() {
    Map<String, String> session = approveAsJohn();
    asks(AuthorizationFlowTest.interaction("ticket-2", null));
    Result again = authorize(session);
    assertEquals("issued straight away", 302, again.status());
    assertEquals(2, fake.count("authorizationIssue"));
    assertEquals(1, audited("CONSENT_REUSED"));
  }

  @Test
  public void anotherBrowserOnlySignsIn() {
    approveAsJohn();
    asks(AuthorizationFlowTest.interaction("ticket-2", null));
    Result page = authorize(Map.of());
    assertTrue("signed out: the sign-in page", contentAsString(page).contains("name=\"identifier\""));
    Result signedIn =
        route(
            app,
            withCsrf(
                    post(
                        "/api/authorization/decision",
                        Map.of("ticket", "ticket-2", "loginId", "john", "password", "john", "login", "true")))
                .session(page.session().data()));
    assertEquals("no consent page after signing in", 302, signedIn.status());
    assertTrue(signedIn.session().get("session_id").isPresent());
    assertEquals(2, fake.count("authorizationIssue"));
  }

  @Test
  public void askingForMoreShowsThePageAgain() {
    Map<String, String> session = approveAsJohn();
    AuthorizationResponse more = AuthorizationFlowTest.interaction("ticket-2", null);
    more.setScopes(new Scope[] {new Scope().setName("openid"), new Scope().setName("profile"), new Scope().setName("email")});
    asks(more);
    Result page = authorize(session);
    assertEquals(200, page.status());
    assertTrue(contentAsString(page).contains("name=\"authorized\""));
    assertEquals(1, fake.count("authorizationIssue"));
  }

  @Test
  public void promptConsentAlwaysAsks() {
    Map<String, String> session = approveAsJohn();
    AuthorizationResponse prompted = AuthorizationFlowTest.interaction("ticket-2", null);
    prompted.setPrompts(new Prompt[] {Prompt.CONSENT});
    asks(prompted);
    assertTrue(contentAsString(authorize(session)).contains("name=\"authorized\""));
  }

  @Test
  public void removingTheAppForgetsTheApproval() {
    Map<String, String> session = approveAsJohn();
    route(app, withCsrf(post("/account/apps/42/remove", Map.of())).session(session));
    asks(AuthorizationFlowTest.interaction("ticket-2", null));
    Result page = authorize(session);
    assertEquals(200, page.status());
    assertTrue(contentAsString(page).contains("name=\"authorized\""));
  }

  @Test
  public void silentSignInNeedsAnApproval() {
    // Signed in, but never approved this app: consent_required.
    Result signedIn =
        route(app, withCsrf(post("/account/login", Map.of("loginId", "john", "password", "john", "next", "account"))));
    asks(AuthorizationFlowTest.interaction("ticket-2", AuthorizationResponse.Action.NO_INTERACTION));
    authorize(signedIn.session().data());
    AuthorizationFailRequest failed = fake.lastRequest("authorizationFail");
    assertEquals(AuthorizationFailRequest.Reason.CONSENT_REQUIRED, failed.getReason());
    assertEquals(0, fake.count("authorizationIssue"));

    // After an approval, prompt=none is issued.
    asks(AuthorizationFlowTest.interaction("ticket-1", null));
    Map<String, String> session = approveAsJohn();
    AuthorizationResponse silent = AuthorizationFlowTest.interaction("ticket-3", AuthorizationResponse.Action.NO_INTERACTION);
    silent.setClaims(null); // Authlete reports no claims for prompt=none.
    asks(silent);
    assertEquals(302, authorize(session).status());
    assertEquals(2, fake.count("authorizationIssue"));
    assertFalse(fake.count("authorizationFail") > 1);
  }
}

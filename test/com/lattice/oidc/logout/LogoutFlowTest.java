package com.lattice.oidc.logout;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.get;
import static com.lattice.oidc.OidcTestSupport.post;
import static com.lattice.oidc.OidcTestSupport.route;
import static com.lattice.oidc.OidcTestSupport.withCsrf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static play.test.Helpers.contentAsString;

import com.authlete.common.dto.BackchannelLogoutTokenResponse;
import com.authlete.common.dto.Client;
import com.authlete.common.dto.NativeSsoLogoutResponse;
import com.lattice.oidc.client.FakeAuthleteApi;
import java.util.Map;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.Application;
import play.mvc.Result;
import play.test.Helpers;

public class LogoutFlowTest {

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private Application app;

  @Before
  public void start() {
    Client client = new Client();
    client.setClientId(42L);
    client.setRedirectUris(new String[] {"https://client.example/cb"});
    fake.answer("getClient", args -> client)
        .answer("backchannelLogoutToken", args -> {
          BackchannelLogoutTokenResponse r = new BackchannelLogoutTokenResponse();
          r.setAction(BackchannelLogoutTokenResponse.Action.OK);
          return r;
        })
        .answer("nativeSsoLogout", args -> new NativeSsoLogoutResponse())
        .answer("authorization", args -> interaction())
        .answer("authorizationIssue", args -> {
          var r = new com.authlete.common.dto.AuthorizationIssueResponse();
          r.setAction(com.authlete.common.dto.AuthorizationIssueResponse.Action.LOCATION);
          r.setResponseContent("https://client.example/cb?code=x");
          return r;
        });
    app = app(fake);
    Helpers.start(app);
  }

  private static com.authlete.common.dto.AuthorizationResponse interaction() {
    var r = new com.authlete.common.dto.AuthorizationResponse();
    r.setAction(com.authlete.common.dto.AuthorizationResponse.Action.INTERACTION);
    r.setTicket("t1");
    Client c = new Client();
    c.setClientId(42L);
    r.setClient(c);
    return r;
  }

  @After
  public void stop() {
    Helpers.stop(app);
  }

  private Map<String, String> loggedInSession() {
    Result page = route(app, withCsrf(get("/api/authorization")));
    Result done =
        route(
            app,
            withCsrf(
                    post(
                        "/api/authorization/decision",
                        Map.of("ticket", "t1", "loginId", "john", "password", "john", "authorized", "true")))
                .session(page.session().data()));
    assertEquals(302, done.status());
    return done.session().data();
  }

  @Test
  public void unregisteredRedirectIsRefused() {
    Result r =
        route(app, get("/api/logout?client_id=42&post_logout_redirect_uri=https://evil.example/"));
    assertEquals(400, r.status());
  }

  @Test
  public void withoutSessionRedirectsToRegisteredUriWithState() {
    Result r =
        route(app, get("/api/logout?client_id=42&post_logout_redirect_uri=https://client.example/cb&state=s1"));
    assertEquals(302, r.status());
    assertEquals("https://client.example/cb?state=s1", r.redirectLocation().orElse(null));
  }

  @Test
  public void sessionWithoutHintNeedsConfirmationThenLogsOutEverywhere() {
    Map<String, String> session = loggedInSession();

    Result confirm = route(app, withCsrf(get("/api/logout")).session(session));
    assertEquals(200, confirm.status());
    assertTrue(contentAsString(confirm).contains("Sign out?"));
    assertEquals(0, fake.count("backchannelLogoutToken"));

    Result done =
        route(app, withCsrf(post("/api/logout/confirm", Map.of("confirm", "true"))).session(session));
    assertEquals(200, done.status());
    assertFalse(done.session().get("sid").isPresent());
    assertEquals("client from the session is notified", 1, fake.count("backchannelLogoutToken"));
    assertEquals(1, fake.count("nativeSsoLogout"));

    // The old cookie no longer represents a login.
    Result again = route(app, withCsrf(get("/api/logout")).session(session));
    assertTrue(contentAsString(again).contains("signed out"));
  }
}

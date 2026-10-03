package com.lattice.oidc.controllers;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.post;
import static com.lattice.oidc.OidcTestSupport.route;
import static com.lattice.oidc.OidcTestSupport.withCsrf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static play.test.Helpers.contentAsString;

import com.authlete.common.dto.DeviceCompleteRequest;
import com.authlete.common.dto.DeviceCompleteResponse;
import com.authlete.common.dto.DeviceVerificationResponse;
import com.authlete.common.dto.Scope;
import com.lattice.oidc.client.FakeAuthleteApi;
import java.util.Map;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.Application;
import play.mvc.Result;
import play.test.Helpers;

/** OAuth 2.0 Device Authorization Grant: the user-facing verification and approval pages. */
public class DeviceFlowTest {

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private Application app;

  @Before
  public void start() {
    fake.answer("deviceVerification", args -> verification(DeviceVerificationResponse.Action.VALID))
        .answer(
            "deviceComplete",
            args -> new DeviceCompleteResponse().setAction(DeviceCompleteResponse.Action.SUCCESS));
    app = app(fake);
    Helpers.start(app);
  }

  @After
  public void stop() {
    Helpers.stop(app);
  }

  private static DeviceVerificationResponse verification(DeviceVerificationResponse.Action action) {
    return new DeviceVerificationResponse()
        .setAction(action)
        .setClientId(42L)
        .setClientName("Living Room TV")
        .setScopes(new Scope[] {new Scope().setName("openid"), new Scope().setName("email")})
        .setClaimNames(new String[] {"name", "email"});
  }

  /** Logs in and enters the code; returns the approval page response. */
  private Result enterCode(String password) {
    return route(
        app,
        withCsrf(
            post(
                "/api/device/verification",
                Map.of("userCode", "WDJB-MJHT", "loginId", "john", "password", password))));
  }

  @Test
  public void approvalPageShowsTheCodeToMatchAndPlainLanguageScopes() {
    Result page = enterCode("john");
    assertEquals(200, page.status());
    String html = contentAsString(page);
    assertTrue(html.contains("Living Room TV"));
    assertTrue("the code is shown so the user can match it", html.contains("WDJB-MJHT"));
    assertTrue(html.contains("Your email address"));
  }

  @Test
  public void approvingCompletesWithTheUserAndClaims() {
    Result page = enterCode("john");
    Result done =
        route(
            app,
            withCsrf(post("/api/device/complete", Map.of("userCode", "WDJB-MJHT", "authorized", "true")))
                .session(page.session().data()));
    assertEquals(200, done.status());
    assertTrue(contentAsString(done).contains("Device authorized"));

    DeviceCompleteRequest req = fake.lastRequest("deviceComplete");
    assertEquals(DeviceCompleteRequest.Result.AUTHORIZED, req.getResult());
    assertEquals("1001", req.getSubject());
    assertTrue(req.getClaims().contains("john@example.com"));
  }

  @Test
  public void denyingCompletesWithAccessDenied() {
    Result page = enterCode("john");
    route(
        app,
        withCsrf(post("/api/device/complete", Map.of("userCode", "WDJB-MJHT", "denied", "true")))
            .session(page.session().data()));
    DeviceCompleteRequest req = fake.lastRequest("deviceComplete");
    assertEquals(DeviceCompleteRequest.Result.ACCESS_DENIED, req.getResult());
    assertEquals(null, req.getSubject());
  }

  @Test
  public void approvalFromAnotherBrowserIsRejected() {
    enterCode("john");
    Result other =
        route(
            app,
            withCsrf(post("/api/device/complete", Map.of("userCode", "WDJB-MJHT", "authorized", "true"))));
    assertEquals(400, other.status());
    assertEquals(0, fake.count("deviceComplete"));
  }

  @Test
  public void approvalIsSingleUse() {
    Result page = enterCode("john");
    Map<String, String> session = page.session().data();
    route(
        app,
        withCsrf(post("/api/device/complete", Map.of("userCode", "WDJB-MJHT", "authorized", "true")))
            .session(session));
    Result replay =
        route(
            app,
            withCsrf(post("/api/device/complete", Map.of("userCode", "WDJB-MJHT", "authorized", "true")))
                .session(session));
    assertEquals(400, replay.status());
    assertEquals(1, fake.count("deviceComplete"));
  }

  @Test
  public void wrongPasswordDoesNotLookUpTheCode() {
    Result r = enterCode("wrong");
    assertEquals(401, r.status());
    assertTrue(contentAsString(r).contains("Invalid login ID or password."));
    assertEquals(0, fake.count("deviceVerification"));
  }

  @Test
  public void expiredAndUnknownCodesAreExplained() {
    fake.answer("deviceVerification", args -> verification(DeviceVerificationResponse.Action.EXPIRED));
    Result expired = enterCode("john");
    assertEquals(400, expired.status());
    assertTrue(contentAsString(expired).contains("expired"));

    fake.answer("deviceVerification", args -> verification(DeviceVerificationResponse.Action.NOT_EXIST));
    Result unknown = enterCode("john");
    assertEquals(404, unknown.status());
    assertTrue(contentAsString(unknown).contains("does not exist"));
  }
}

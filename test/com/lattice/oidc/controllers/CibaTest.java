package com.lattice.oidc.controllers;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.post;
import static com.lattice.oidc.OidcTestSupport.route;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.authlete.common.dto.BackchannelAuthenticationCompleteRequest;
import com.authlete.common.dto.BackchannelAuthenticationCompleteResponse;
import com.authlete.common.dto.BackchannelAuthenticationFailRequest;
import com.authlete.common.dto.BackchannelAuthenticationFailResponse;
import com.authlete.common.dto.BackchannelAuthenticationIssueResponse;
import com.authlete.common.dto.BackchannelAuthenticationResponse;
import com.authlete.common.dto.Scope;
import com.authlete.common.types.UserIdentificationHintType;
import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.common.Jsons;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import org.junit.After;
import org.junit.Test;
import play.Application;
import play.mvc.Http;
import play.mvc.Result;
import play.test.Helpers;

/**
 * CIBA: user identification checks before an auth_req_id is issued, and completion from the
 * authentication device (a local stand-in for Authlete's CIBA simulator) in sync and async modes.
 */
public class CibaTest {

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private final List<Map<String, Object>> deviceRequests = new CopyOnWriteArrayList<>();
  private volatile String syncResult = "allow";
  private HttpServer device;
  private Application app;

  private void start(String mode) throws Exception {
    device = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    device.createContext(
        "/api/authenticate/",
        ex -> {
          Map<String, Object> body =
              new HashMap<>(
                  Jsons.readMap(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
          body.put("path", ex.getRequestURI().getPath());
          deviceRequests.add(body);
          String response =
              ex.getRequestURI().getPath().endsWith("/sync")
                  ? "{\"result\":\"" + syncResult + "\"}"
                  : "{\"request_id\":\"dev-failRequest-1\"}";
          byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
          ex.sendResponseHeaders(200, bytes.length);
          ex.getResponseBody().write(bytes);
          ex.close();
        });
    device.start();

    fake.answer(
            "backchannelAuthenticationIssue",
            args ->
                new BackchannelAuthenticationIssueResponse()
                    .setAction(BackchannelAuthenticationIssueResponse.Action.OK)
                    .setAuthReqId("arid-1")
                    .setExpiresIn(120)
                    .setResponseContent("{\"auth_req_id\":\"arid-1\",\"expires_in\":120}"))
        .answer(
            "backchannelAuthenticationFail",
            args ->
                new BackchannelAuthenticationFailResponse()
                    .setAction(BackchannelAuthenticationFailResponse.Action.BAD_REQUEST)
                    .setResponseContent("{\"error\":\"failed\"}"))
        .answer(
            "backchannelAuthenticationComplete",
            args ->
                new BackchannelAuthenticationCompleteResponse()
                    .setAction(BackchannelAuthenticationCompleteResponse.Action.NO_ACTION));
    authleteSays(r -> {});
    app =
        app(
            fake,
            Map.of(
                "lattice.ciba.mode", mode,
                "lattice.ciba.base-url", "http://127.0.0.1:" + device.getAddress().getPort(),
                "lattice.ciba.workspace", "test-workspace"));
    Helpers.start(app);
  }

  @After
  public void stop() {
    if (app != null) {
      Helpers.stop(app);
    }
    if (device != null) {
      device.stop(0);
    }
  }

  /** Scripts the /backchannel/authentication response: john by email, adjustable by {@code setup}. */
  private void authleteSays(Consumer<BackchannelAuthenticationResponse> setup) {
    fake.answer(
        "backchannelAuthentication",
        args -> {
          BackchannelAuthenticationResponse r =
              new BackchannelAuthenticationResponse()
                  .setAction(BackchannelAuthenticationResponse.Action.USER_IDENTIFICATION)
                  .setTicket("ciba-ticket")
                  .setClientName("Bank App")
                  .setScopes(new Scope[] {new Scope().setName("openid")})
                  .setClaimNames(new String[] {"email"})
                  .setHintType(UserIdentificationHintType.LOGIN_HINT)
                  .setHint("john@example.com");
          setup.accept(r);
          return r;
        });
  }

  private Result authenticate() {
    return route(app, post("/api/backchannel/authentication", Map.of("login_hint", "john@example.com")));
  }

  private BackchannelAuthenticationFailRequest.Reason failureReason() {
    BackchannelAuthenticationFailRequest failRequest = fake.lastRequest("backchannelAuthenticationFail");
    return failRequest.getReason();
  }

  /** Waits for the background interaction with the device to call Authlete's complete API. */
  private BackchannelAuthenticationCompleteRequest awaitCompletion() throws InterruptedException {
    long deadline = System.currentTimeMillis() + 10_000;
    while (fake.count("backchannelAuthenticationComplete") == 0) {
      if (System.currentTimeMillis() > deadline) {
        fail("backchannelAuthenticationComplete was not called");
      }
      Thread.sleep(20);
    }
    return fake.lastRequest("backchannelAuthenticationComplete");
  }

  /** Sends the device's callback, retrying while the background task has not cached the request yet. */
  private Result awaitAcceptedCallback(String body) throws InterruptedException {
    long deadline = System.currentTimeMillis() + 10_000;
    while (true) {
      Result r = deviceCallback(body);
      if (r.status() != 400 || System.currentTimeMillis() > deadline) {
        return r;
      }
      Thread.sleep(20);
    }
  }

  private Result deviceCallback(String body) {
    return route(
        app,
        new Http.RequestBuilder()
            .method("POST")
            .uri("/api/backchannel/authentication/callback")
            .bodyText(body)
            .header("Content-Type", "application/json"));
  }

  @Test
  public void syncApprovalCompletesWithTheUsersClaims() throws Exception {
    start("sync");
    Result r = authenticate();
    assertEquals(200, r.status());
    assertTrue(Helpers.contentAsString(r).contains("arid-1"));

    BackchannelAuthenticationCompleteRequest done = awaitCompletion();
    assertEquals(BackchannelAuthenticationCompleteRequest.Result.AUTHORIZED, done.getResult());
    assertEquals("1001", done.getSubject());
    assertTrue(done.getClaims().contains("john@example.com"));

    Map<String, Object> sent = deviceRequests.get(0);
    assertEquals("1001", sent.get("user"));
    assertEquals("arid-1", sent.get("actionize_token"));
    assertTrue(String.valueOf(sent.get("message")).contains("Bank App"));
  }

  @Test
  public void syncDenialCompletesWithAccessDenied() throws Exception {
    syncResult = "deny";
    start("sync");
    authenticate();
    BackchannelAuthenticationCompleteRequest done = awaitCompletion();
    assertEquals(BackchannelAuthenticationCompleteRequest.Result.ACCESS_DENIED, done.getResult());
    assertEquals(null, done.getClaims());
  }

  @Test
  public void unknownUserFailsWithoutIssuing() throws Exception {
    start("sync");
    authleteSays(r -> r.setHint("nobody@example.com"));
    assertEquals(400, authenticate().status());
    assertEquals(BackchannelAuthenticationFailRequest.Reason.UNKNOWN_USER_ID, failureReason());
    assertEquals(0, fake.count("backchannelAuthenticationIssue"));
  }

  @Test
  public void wrongUserCodeFailsWithoutIssuing() throws Exception {
    start("sync");
    authleteSays(r -> r.setUserCodeRequired(true).setUserCode("000000"));
    assertEquals(400, authenticate().status());
    assertEquals(BackchannelAuthenticationFailRequest.Reason.INVALID_USER_CODE, failureReason());

    authleteSays(r -> r.setUserCodeRequired(true).setUserCode("675325"));
    assertEquals(200, authenticate().status());
  }

  @Test
  public void unprintableOrOverlongBindingMessageIsRejected() throws Exception {
    start("sync");
    authleteSays(r -> r.setBindingMessage("Pay 100\u0007"));
    assertEquals(400, authenticate().status());
    assertEquals(BackchannelAuthenticationFailRequest.Reason.INVALID_BINDING_MESSAGE, failureReason());

    authleteSays(r -> r.setBindingMessage("x".repeat(129)));
    assertEquals(400, authenticate().status());
    assertEquals(0, fake.count("backchannelAuthenticationIssue"));
  }

  @Test
  public void loginHintTokensAreNotSupported() throws Exception {
    start("sync");
    authleteSays(r -> r.setHintType(UserIdentificationHintType.LOGIN_HINT_TOKEN).setHint("1001"));
    assertEquals(400, authenticate().status());
    assertEquals(BackchannelAuthenticationFailRequest.Reason.UNKNOWN_USER_ID, failureReason());
    assertEquals(0, fake.count("backchannelAuthenticationIssue"));
  }

  @Test
  public void asyncCallbackCompletesOnlyAKnownRequestOnce() throws Exception {
    start("async");
    assertEquals(200, authenticate().status());
    assertEquals(400, deviceCallback("{\"request_id\":\"forged\",\"result\":\"allow\"}").status());

    assertEquals(204, awaitAcceptedCallback("{\"request_id\":\"dev-failRequest-1\",\"result\":\"allow\"}").status());
    assertTrue(String.valueOf(deviceRequests.get(0).get("path")).endsWith("/async"));
    BackchannelAuthenticationCompleteRequest done = fake.lastRequest("backchannelAuthenticationComplete");
    assertEquals(BackchannelAuthenticationCompleteRequest.Result.AUTHORIZED, done.getResult());

    assertEquals(
        "the request id is single-use",
        400,
        deviceCallback("{\"request_id\":\"dev-failRequest-1\",\"result\":\"allow\"}").status());
    assertEquals(1, fake.count("backchannelAuthenticationComplete"));
  }

  @Test
  public void malformedCallbacksAreRejected() throws Exception {
    start("async");
    assertEquals(400, deviceCallback("not json").status());
    assertEquals(400, deviceCallback("{\"result\":\"allow\"}").status());
    assertEquals(400, deviceCallback("{\"request_id\":\"dev-failRequest-1\"}").status());
  }
}

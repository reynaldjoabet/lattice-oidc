package com.lattice.oidc.controllers;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.route;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static play.test.Helpers.contentAsString;

import com.authlete.common.dto.GMRequest;
import com.authlete.common.dto.GMResponse;
import com.authlete.common.types.GMAction;
import com.lattice.oidc.client.FakeAuthleteApi;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.Application;
import play.mvc.Http;
import play.mvc.Result;
import play.test.Helpers;

/** The Grant Management endpoint: query and revoke, and how Authlete's answers become HTTP responses. */
public class GrantManagementTest {

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private Application app;

  @Before
  public void start() {
    app = app(fake);
    Helpers.start(app);
  }

  @After
  public void stop() {
    Helpers.stop(app);
  }

  private void authleteSays(GMResponse.Action action, String content) {
    fake.answer(
        "gm",
        args -> {
          GMResponse r = new GMResponse();
          r.setAction(action);
          r.setResponseContent(content);
          r.setResultMessage("[A999] internal detail");
          return r;
        });
  }

  private static Http.RequestBuilder request(String method) {
    return new Http.RequestBuilder().method(method).uri("/api/gm/grant-1").header("Authorization", "Bearer at-123");
  }

  @Test
  public void aQueryReturnsTheGrant() {
    String grant = "{\"scopes\":[{\"scope\":\"openid accounts\"}],\"claims\":[\"name\"]}";
    authleteSays(GMResponse.Action.OK, grant);
    Result r = route(app, request("GET"));
    assertEquals(200, r.status());
    assertTrue(r.contentType().orElse("").startsWith("application/json"));
    assertEquals(grant, contentAsString(r));
    GMRequest sent = fake.lastRequest("gm");
    assertEquals(GMAction.QUERY, sent.getGmAction());
    assertEquals("grant-1", sent.getGrantId());
    assertEquals("at-123", sent.getAccessToken());
    assertEquals("GET", sent.getHtm());
  }

  @Test
  public void aRevocationIs204() {
    authleteSays(GMResponse.Action.NO_CONTENT, null);
    Result r = route(app, request("DELETE"));
    assertEquals(204, r.status());
    GMRequest sent = fake.lastRequest("gm");
    assertEquals(GMAction.REVOKE, sent.getGmAction());
    assertEquals("DELETE", sent.getHtm());
  }

  @Test
  public void errorsCarryAuthletesChallengeInWwwAuthenticateWithNoBody() {
    String challenge = "Bearer error=\"invalid_token\", error_description=\"[A065304] The access token has expired.\"";
    int[][] cases = {{401}, {403}, {404}};
    GMResponse.Action[] actions = {GMResponse.Action.UNAUTHORIZED, GMResponse.Action.FORBIDDEN, GMResponse.Action.NOT_FOUND};
    for (int i = 0; i < actions.length; i++) {
      authleteSays(actions[i], challenge);
      Result r = route(app, request("GET"));
      assertEquals(actions[i].name(), cases[i][0], r.status());
      assertEquals(actions[i].name(), challenge, r.header("WWW-Authenticate").orElse(null));
      assertEquals(actions[i].name(), "", contentAsString(r));
    }
  }

  @Test
  public void aDpopNonceIsPassedOn() {
    fake.answer(
        "gm",
        args -> {
          GMResponse r = new GMResponse();
          r.setAction(GMResponse.Action.UNAUTHORIZED);
          r.setResponseContent("DPoP error=\"use_dpop_nonce\"");
          r.setDpopNonce("nonce-1");
          return r;
        });
    Result r = route(app, request("GET").header("DPoP", "proof"));
    assertEquals(401, r.status());
    assertEquals("nonce-1", r.header("DPoP-Nonce").orElse(null));
    assertEquals("DPoP error=\"use_dpop_nonce\"", r.header("WWW-Authenticate").orElse(null));
    assertEquals("proof", ((GMRequest) fake.lastRequest("gm")).getDpop());
  }

  @Test
  public void authletesInternalErrorsAreNotShownToTheClient() {
    for (GMResponse.Action action : new GMResponse.Action[] {GMResponse.Action.CALLER_ERROR, GMResponse.Action.AUTHLETE_ERROR}) {
      authleteSays(action, "Bearer error=\"server_error\", error_description=\"internal detail\"");
      Result r = route(app, request("GET"));
      assertEquals(action.name(), 500, r.status());
      assertTrue(action.name(), contentAsString(r).contains("server_error"));
      assertFalse(action.name(), contentAsString(r).contains("internal detail"));
    }
  }
}

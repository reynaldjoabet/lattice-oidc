package com.lattice.oidc.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.api.AuthleteApiException;
import com.authlete.common.conf.AuthleteSimpleConfiguration;
import com.authlete.common.dto.AuthorizationIssueRequest;
import com.authlete.common.dto.AuthorizationRequest;
import com.authlete.common.dto.AuthorizationResponse;
import com.authlete.common.dto.TokenListResponse;
import com.authlete.common.types.SubjectType;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.libs.ws.WSClient;
import play.mvc.Http;
import play.mvc.Results;
import play.routing.RoutingDsl;
import play.server.Server;
import play.test.WSTestClient;
import tools.jackson.databind.JsonNode;

public class PlayAuthleteApiV3Test {

  private static final String AUTHORIZATION_RESPONSE =
      """
      {
        "resultCode": "A004001",
        "resultMessage": "[A004001] Authlete has successfully issued a ticket.",
        "action": "INTERACTION",
        "ticket": "ticket-123",
        "maxAge": 600,
        "acrEssential": true,
        "acrs": ["urn:mace:incommon:iap:silver"],
        "client": {"clientId": 5899, "clientName": "Demo", "subjectType": "PAIRWISE"},
        "service": {"serviceName": "Lattice"},
        "scopes": [{"name": "openid"}, {"name": "profile"}],
        "aFieldFromANewerAuthlete": {"nested": true}
      }
      """;

  private final Map<String, Http.Request> seen = new ConcurrentHashMap<>();
  private Server server;
  private WSClient ws;
  private AuthleteApi api;

  @Before
  public void setUp() {
    server =
        Server.forRouter(
            components ->
                RoutingDsl.fromComponents(components)
                    .POST("/api/42/auth/authorization")
                    .routingTo(
                        req -> {
                          seen.put("authorization", req);
                          return Results.ok(AUTHORIZATION_RESPONSE).as("application/json");
                        })
                    .POST("/api/42/auth/authorization/issue")
                    .routingTo(
                        req -> {
                          seen.put("issue", req);
                          return Results.status(503, "{\"resultMessage\":\"down\"}")
                              .as("application/json");
                        })
                    .GET("/api/42/auth/token/get/list")
                    .routingTo(
                        req -> {
                          seen.put("tokens", req);
                          return Results.ok("{\"start\":0,\"end\":5,\"totalCount\":0}")
                              .as("application/json");
                        })
                    .build());
    ws = WSTestClient.newClient(server.httpPort());
    AuthleteSimpleConfiguration configuration =
        new AuthleteSimpleConfiguration()
            .setApiVersion("V3")
            .setBaseUrl("http://localhost:" + server.httpPort())
            .setServiceApiKey("42")
            .setServiceAccessToken("secret-token");
    api = new PlayAuthleteApiV3(configuration, ws);
  }

  @After
  public void tearDown() throws Exception {
    ws.close();
    server.stop();
  }

  @Test
  public void postsJsonToServiceScopedPathAndMapsResponse() {
    AuthorizationResponse response =
        api.authorization(new AuthorizationRequest().setParameters("response_type=code"));

    Http.Request req = seen.get("authorization");
    assertEquals("Bearer secret-token", req.header("Authorization").orElse(null));
    assertTrue(req.contentType().orElse("").startsWith("application/json"));
    JsonNode body = AuthleteJson.mapper().readTree(req.body().asJson().toString());
    assertEquals("response_type=code", body.get("parameters").asString());
    assertTrue("nulls must not be sent", body.get("context") == null);

    assertEquals(AuthorizationResponse.Action.INTERACTION, response.getAction());
    assertEquals("ticket-123", response.getTicket());
    assertEquals(600, response.getMaxAge());
    assertTrue(response.isAcrEssential());
    assertEquals(5899L, response.getClient().getClientId());
    assertEquals(SubjectType.PAIRWISE, response.getClient().getSubjectType());
    assertEquals("Lattice", response.getService().getServiceName());
    assertEquals("profile", response.getScopes()[1].getName());
    assertTrue(response.getResponseHeaders().keySet().stream()
        .anyMatch(h -> h.equalsIgnoreCase("Content-Type")));
  }

  @Test
  public void writesEnumsByName() {
    String json =
        AuthleteJson.mapper()
            .writeValueAsString(
                new com.authlete.common.dto.AuthorizationFailRequest()
                    .setTicket("t")
                    .setReason(com.authlete.common.dto.AuthorizationFailRequest.Reason.NOT_LOGGED_IN));
    assertTrue(json, json.contains("\"reason\":\"NOT_LOGGED_IN\""));
  }

  @Test
  public void mapsHttpErrorsToAuthleteApiException() {
    try {
      api.authorizationIssue(new AuthorizationIssueRequest().setTicket("t").setSubject("s"));
      fail("expected AuthleteApiException");
    } catch (AuthleteApiException e) {
      assertEquals(503, e.getStatusCode());
      assertEquals("{\"resultMessage\":\"down\"}", e.getResponseBody());
    }
  }

  @Test
  public void sendsQueryParametersForListApis() {
    TokenListResponse response = api.getTokenList("client-1", "user-1", 0, 5);
    Http.Request req = seen.get("tokens");
    assertEquals("client-1", req.queryString("clientIdentifier").orElse(null));
    assertEquals("user-1", req.queryString("subject").orElse(null));
    assertEquals("5", req.queryString("end").orElse(null));
    assertEquals("ALL", req.queryString("tokenStatus").orElse(null));
    assertEquals(5, response.getEnd());
    assertNull(response.getAccessTokens());
  }

  @Test
  public void transportFailuresHaveNoStatusCode() throws Exception {
    AuthleteSimpleConfiguration configuration =
        new AuthleteSimpleConfiguration()
            .setApiVersion("V3")
            .setBaseUrl("http://localhost:1")
            .setServiceApiKey("42")
            .setServiceAccessToken("t");
    try {
      new PlayAuthleteApiV3(configuration, ws).authorization(new AuthorizationRequest());
      fail("expected AuthleteApiException");
    } catch (AuthleteApiException e) {
      assertEquals(0, e.getStatusCode());
    }
  }
}

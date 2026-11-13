package com.lattice.oidc.controllers;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.post;
import static com.lattice.oidc.OidcTestSupport.route;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static play.test.Helpers.contentAsString;

import com.authlete.common.dto.PushedAuthReqResponse;
import com.authlete.common.dto.TokenResponse;
import com.lattice.oidc.client.FakeAuthleteApi;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.util.Map;
import org.junit.After;
import org.junit.Test;
import play.Application;
import play.mvc.Result;
import play.test.Helpers;

/** RFC 10070: client assertions must name only the issuer as audience, checked before Authlete. */
public class ClientAssertionAudienceEndpointsTest {

  private static final String ISSUER = "https://as.example";
  private static final String JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private Application app;

  private void start(Map<String, Object> config) {
    fake.answer(
        "getServiceConfiguration",
        args -> "{\"issuer\":\"" + ISSUER + "\",\"token_endpoint\":\"" + ISSUER + "/api/token\"}");
    fake.answer("getServiceJwks", args -> "{\"keys\":[]}");
    fake.answer(
        "token",
        args -> {
          TokenResponse r = new TokenResponse();
          r.setAction(TokenResponse.Action.INVALID_CLIENT);
          r.setResponseContent("{\"error\":\"invalid_client\"}");
          return r;
        });
    fake.answer(
        "pushAuthorizationRequest",
        args -> {
          PushedAuthReqResponse r = new PushedAuthReqResponse();
          r.setAction(PushedAuthReqResponse.Action.CREATED);
          r.setResponseContent("{\"request_uri\":\"urn:x\",\"expires_in\":60}");
          return r;
        });
    app = app(fake, config);
    Helpers.start(app);
  }

  @After
  public void stop() {
    if (app != null) {
      Helpers.stop(app);
    }
  }

  private static String assertion(String audience) throws Exception {
    SignedJWT jwt =
        new SignedJWT(
            new JWSHeader(JWSAlgorithm.HS256),
            new JWTClaimsSet.Builder().issuer("c1").subject("c1").audience(audience).build());
    jwt.sign(new MACSigner(new byte[32]));
    return jwt.serialize();
  }

  private Result token(String audience) throws Exception {
    return route(
        app,
        post(
            "/api/token",
            Map.of(
                "grant_type",
                "client_credentials",
                "client_id",
                "c1",
                "client_assertion_type",
                JWT_BEARER,
                "client_assertion",
                assertion(audience))));
  }

  @Test
  public void theTokenEndpointRefusesAnAssertionForTheTokenEndpointUrl() throws Exception {
    start(Map.of());
    Result r = token(ISSUER + "/api/token");
    assertEquals(401, r.status());
    assertTrue(contentAsString(r).contains("invalid_client"));
    assertEquals(0, fake.count("token"));
  }

  @Test
  public void theTokenEndpointPassesAnAssertionForTheIssuerToAuthlete() throws Exception {
    start(Map.of());
    token(ISSUER);
    assertEquals(1, fake.count("token"));
  }

  @Test
  public void parRefusesAnAssertionForThePushedAuthorizationEndpoint() throws Exception {
    start(Map.of());
    Result r =
        route(
            app,
            post(
                "/api/par",
                Map.of(
                    "response_type",
                    "code",
                    "client_id",
                    "c1",
                    "client_assertion_type",
                    JWT_BEARER,
                    "client_assertion",
                    assertion(ISSUER + "/api/par"))));
    assertEquals(401, r.status());
    assertEquals(0, fake.count("pushAuthorizationRequest"));
  }

  @Test
  public void withStrictAudienceOffTheAssertionIsOnlyLogged() throws Exception {
    start(Map.of("lattice.client-assertion.strict-audience", false));
    token(ISSUER + "/api/token");
    assertEquals(1, fake.count("token"));
  }
}

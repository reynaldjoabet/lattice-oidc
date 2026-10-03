package com.lattice.oidc.controllers;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.post;
import static com.lattice.oidc.OidcTestSupport.route;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static play.test.Helpers.contentAsString;

import com.authlete.common.dto.NativeSsoRequest;
import com.authlete.common.dto.NativeSsoResponse;
import com.authlete.common.dto.TokenCreateRequest;
import com.authlete.common.dto.TokenCreateResponse;
import com.authlete.common.dto.TokenInfo;
import com.authlete.common.dto.TokenResponse;
import com.authlete.common.types.TokenType;
import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.handlers.FakeUpstreamProvider;
import com.lattice.oidc.models.User;
import com.lattice.oidc.security.UserSessions;
import com.lattice.oidc.stores.UserStore;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.Application;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;
import play.test.Helpers;

/**
 * Grants Authlete delegates to this server: token exchange (RFC 8693), JWT bearer (RFC 7523) and
 * Native SSO. Subject JWTs must be signed by a trusted issuer; device secrets are bound to a live
 * login session.
 */
public class TokenGrantsTest {

  private static final String ISSUER = "https://lattice.example";

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private FakeUpstreamProvider trusted;
  private FakeUpstreamProvider untrusted;
  private Application app;

  @Before
  public void start() throws Exception {
    trusted = new FakeUpstreamProvider();
    untrusted = new FakeUpstreamProvider();
    fake.answer("getServiceConfiguration", args -> "{\"issuer\":\"" + ISSUER + "\",\"token_endpoint\":\"" + ISSUER + "/api/token\"}")
        .answer("getServiceJwks", args -> "{\"keys\":[]}")
        .answer(
            "tokenCreate",
            args -> new TokenCreateResponse().setAction(TokenCreateResponse.Action.OK).setAccessToken("new-at").setExpiresIn(3600))
        .answer(
            "nativeSso",
            args ->
                new NativeSsoResponse()
                    .setAction(NativeSsoResponse.Action.OK)
                    .setResponseContent("{\"access_token\":\"at\",\"device_secret\":\"ds\"}"));
    app =
        app(
            fake,
            Map.of(
                "lattice.trusted-jwt-issuers",
                List.of(Map.of("issuer", trusted.issuer, "jwks-uri", trusted.jwksUri()))));
    Helpers.start(app);
  }

  @After
  public void stop() {
    Helpers.stop(app);
    trusted.close();
    untrusted.close();
  }

  /** Scripts Authlete's /auth/token response. */
  private void authleteSays(TokenResponse.Action action, Consumer<TokenResponse> setup) {
    fake.answer(
        "token",
        args -> {
          TokenResponse r = new TokenResponse();
          r.setAction(action);
          r.setClientId(42L);
          r.setScopes(new String[] {"openid"});
          setup.accept(r);
          return r;
        });
  }

  private Result tokenRequest() {
    return route(app, post("/api/token", Map.of("grant_type", "anything")));
  }

  private void exchangeJwt(String jwt) {
    authleteSays(
        TokenResponse.Action.TOKEN_EXCHANGE,
        r -> {
          r.setSubjectTokenType(TokenType.JWT);
          r.setSubjectToken(jwt);
        });
  }

  @Test
  public void exchangeOfJwtFromTrustedIssuerCreatesTokenForItsSubject() {
    exchangeJwt(trusted.jwt(trusted.issuer, "alice", null));
    Result r = tokenRequest();
    assertEquals(200, r.status());
    assertTrue(contentAsString(r).contains("urn:ietf:params:oauth:token-type:access_token"));
    TokenCreateRequest created = fake.lastRequest("tokenCreate");
    assertEquals("alice", created.getSubject());
    assertEquals(42L, created.getClientId());
  }

  @Test
  public void exchangeOfJwtFromUntrustedIssuerIsRejected() {
    exchangeJwt(untrusted.jwt(untrusted.issuer, "alice", null));
    assertEquals(400, tokenRequest().status());
    assertEquals(0, fake.count("tokenCreate"));
  }

  @Test
  public void jwtClaimingTheTrustedIssuerButSignedByAnotherKeyIsRejected() {
    exchangeJwt(untrusted.jwt(trusted.issuer, "alice", null));
    assertEquals(400, tokenRequest().status());
    assertEquals(0, fake.count("tokenCreate"));
  }

  @Test
  public void exchangeOfAccessTokenUsesTheSubjectAuthleteValidated() {
    authleteSays(
        TokenResponse.Action.TOKEN_EXCHANGE,
        r -> {
          r.setSubjectTokenType(TokenType.ACCESS_TOKEN);
          r.setSubjectToken("at-from-this-server");
          r.setSubjectTokenInfo(new TokenInfo().setSubject("1001"));
        });
    assertEquals(200, tokenRequest().status());
    assertEquals("1001", ((TokenCreateRequest) fake.lastRequest("tokenCreate")).getSubject());
  }

  @Test
  public void anonymousClientsCannotExchangeAndSamlIsUnsupported() {
    authleteSays(
        TokenResponse.Action.TOKEN_EXCHANGE,
        r -> {
          r.setClientId(0);
          r.setSubjectTokenType(TokenType.JWT);
          r.setSubjectToken(trusted.jwt(trusted.issuer, "alice", null));
        });
    assertEquals(400, tokenRequest().status());

    authleteSays(
        TokenResponse.Action.TOKEN_EXCHANGE,
        r -> {
          r.setSubjectTokenType(TokenType.SAML2);
          r.setSubjectToken("<saml/>");
        });
    assertEquals(400, tokenRequest().status());
    assertEquals(0, fake.count("tokenCreate"));
  }

  @Test
  public void jwtBearerAssertionMustBeAddressedToThisServer() {
    authleteSays(
        TokenResponse.Action.JWT_BEARER,
        r -> r.setAssertion(trusted.jwt(trusted.issuer, "alice", "https://other.example")));
    Result wrongAudience = tokenRequest();
    assertEquals(400, wrongAudience.status());
    assertTrue(contentAsString(wrongAudience).contains("invalid_grant"));

    authleteSays(
        TokenResponse.Action.JWT_BEARER,
        r -> r.setAssertion(trusted.jwt(trusted.issuer, "alice", ISSUER + "/api/token")));
    assertEquals(200, tokenRequest().status());
    assertEquals("alice", ((TokenCreateRequest) fake.lastRequest("tokenCreate")).getSubject());
  }

  // --- Native SSO ---

  private String login() {
    UserSessions sessions = app.injector().instanceOf(UserSessions.class);
    User john = app.injector().instanceOf(UserStore.class).bySubject("1001").orElseThrow();
    return sessions.login(john, System.currentTimeMillis() / 1000L, null, new HashMap<>());
  }

  private void nativeSso(String sessionId, String deviceSecret, String deviceSecretHash) {
    authleteSays(
        TokenResponse.Action.NATIVE_SSO,
        r -> {
          r.setSessionId(sessionId);
          r.setAccessToken("at");
          r.setDeviceSecret(deviceSecret);
          r.setDeviceSecretHash(deviceSecretHash);
        });
  }

  @Test
  public void nativeSsoIssuesADeviceSecretAndReusesItForTheSameSession() {
    String sessionId = login();
    nativeSso(sessionId, null, null);
    assertEquals(200, tokenRequest().status());
    NativeSsoRequest first = fake.lastRequest("nativeSso");
    assertNotNull(first.getDeviceSecret());

    // Token exchange by a second app on the device, presenting the secret and its hash.
    nativeSso(sessionId, first.getDeviceSecret(), first.getDeviceSecretHash());
    assertEquals(200, tokenRequest().status());
    NativeSsoRequest second = fake.lastRequest("nativeSso");
    assertEquals(first.getDeviceSecret(), second.getDeviceSecret());
  }

  @Test
  public void deviceSecretWithWrongHashOrFromAnotherSessionIsRejected() {
    String sessionId = login();
    nativeSso(sessionId, null, null);
    tokenRequest();
    NativeSsoRequest issued = fake.lastRequest("nativeSso");

    nativeSso(sessionId, issued.getDeviceSecret(), "wrong-hash");
    Result wrongHash = tokenRequest();
    assertEquals(400, wrongHash.status());
    assertTrue(contentAsString(wrongHash).contains("invalid_grant"));

    String otherSessionId = login();
    nativeSso(otherSessionId, issued.getDeviceSecret(), issued.getDeviceSecretHash());
    assertEquals(400, tokenRequest().status());
    assertEquals(1, fake.count("nativeSso"));
  }

  @Test
  public void unknownDeviceSecretInARegularFlowIsReplaced() {
    String sessionId = login();
    nativeSso(sessionId, "stale-secret", null);
    assertEquals(200, tokenRequest().status());
    assertNotEquals("stale-secret", ((NativeSsoRequest) fake.lastRequest("nativeSso")).getDeviceSecret());
  }

  @Test
  public void nativeSsoStopsWorkingWhenTheLoginSessionEnds() {
    String sessionId = login();
    nativeSso(sessionId, null, null);
    tokenRequest();
    NativeSsoRequest issued = fake.lastRequest("nativeSso");

    app.injector()
        .instanceOf(UserSessions.class)
        .logout(Results.ok(), new Http.RequestBuilder().build(), sessionId);
    nativeSso(sessionId, issued.getDeviceSecret(), issued.getDeviceSecretHash());
    Result r = tokenRequest();
    assertEquals(400, r.status());
    assertTrue(contentAsString(r).contains("invalid_grant"));
  }
}

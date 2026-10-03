package com.lattice.oidc.controllers;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.get;
import static com.lattice.oidc.OidcTestSupport.post;
import static com.lattice.oidc.OidcTestSupport.route;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static play.test.Helpers.contentAsString;

import com.authlete.common.dto.BackchannelAuthenticationFailRequest;
import com.authlete.common.dto.BackchannelAuthenticationFailResponse;
import com.authlete.common.dto.BackchannelAuthenticationResponse;
import com.authlete.common.dto.StandardIntrospectionResponse;
import com.authlete.common.dto.TokenRequest;
import com.authlete.common.dto.TokenResponse;
import com.authlete.common.dto.UserInfoIssueRequest;
import com.authlete.common.dto.UserInfoIssueResponse;
import com.authlete.common.dto.UserInfoResponse;
import com.authlete.common.types.UserIdentificationHintType;
import com.lattice.oidc.client.FakeAuthleteApi;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.Application;
import play.mvc.Result;
import play.test.Helpers;

public class ProtocolEndpointsTest {

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

  private static String basic(String id, String secret) {
    return "Basic " + Base64.getEncoder().encodeToString((id + ":" + secret).getBytes());
  }

  private static TokenResponse token(TokenResponse.Action action, String content) {
    TokenResponse r = new TokenResponse();
    r.setAction(action);
    r.setResponseContent(content);
    return r;
  }

  @Test
  public void tokenForwardsClientCredentialsAndMapsInvalidClient() {
    fake.answer(
        "token",
        args -> {
          TokenResponse r = token(TokenResponse.Action.INVALID_CLIENT, "{\"error\":\"invalid_client\"}");
          r.setDpopNonce("nonce-1");
          return r;
        });
    Result r =
        route(
            app,
            post("/api/token", Map.of("grant_type", "authorization_code", "code", "a b"))
                .header("Authorization", basic("client", "secret"))
                .header("DPoP", "proof"));
    assertEquals(401, r.status());
    assertEquals("Basic realm=\"token\"", r.header("WWW-Authenticate").orElse(null));
    assertEquals("nonce-1", r.header("DPoP-Nonce").orElse(null));
    assertEquals("no-store", r.header("Cache-Control").orElse(null));

    TokenRequest sent = fake.lastRequest("token");
    assertEquals("client", sent.getClientId());
    assertEquals("secret", sent.getClientSecret());
    assertEquals("proof", sent.getDpop());
    assertTrue(sent.getParameters().contains("code=a+b"));
  }

  @Test
  public void passwordGrantAuthenticatesAgainstUserStore() {
    fake.answer(
            "token",
            args -> {
              TokenResponse r = token(TokenResponse.Action.PASSWORD, null);
              r.setUsername("jane");
              r.setPassword("wrong");
              r.setTicket("t");
              return r;
            })
        .answer(
            "tokenFail",
            args -> {
              var f = new com.authlete.common.dto.TokenFailResponse();
              f.setAction(com.authlete.common.dto.TokenFailResponse.Action.BAD_REQUEST);
              f.setResponseContent("{\"error\":\"invalid_grant\"}");
              return f;
            });
    Result r = route(app, post("/api/token", Map.of("grant_type", "password")));
    assertEquals(400, r.status());
    assertEquals(0, fake.count("tokenIssue"));
  }

  @Test
  public void jwtBearerRejectsAssertionsFromUntrustedIssuers() throws Exception {
    RSAKey key = new RSAKeyGenerator(2048).keyID("k").generate();
    fake.answer("getServiceConfiguration", args -> "{\"issuer\":\"https://as.example\",\"token_endpoint\":\"https://as.example/api/token\"}")
        .answer("getServiceJwks", args -> "{\"keys\":[]}")
        .answer(
            "token",
            args -> {
              SignedJWT jwt =
                  new SignedJWT(
                      new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("k").build(),
                      new JWTClaimsSet.Builder()
                          .issuer("https://evil.example")
                          .subject("1001")
                          .audience("https://as.example")
                          .expirationTime(new Date(System.currentTimeMillis() + 60_000))
                          .build());
              try {
                jwt.sign(new RSASSASigner(key));
              } catch (Exception e) {
                throw new IllegalStateException(e);
              }
              TokenResponse t = token(TokenResponse.Action.JWT_BEARER, null);
              t.setClientId(7L);
              t.setAssertion(jwt.serialize());
              return t;
            });
    Result r = route(app, post("/api/token", Map.of("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")));
    assertEquals(400, r.status());
    assertTrue(contentAsString(r).contains("invalid_grant"));
    assertTrue(contentAsString(r).contains("not trusted"));
    assertEquals(0, fake.count("tokenCreate"));
  }

  @Test
  public void introspectionRequiresResourceServerCredentials() {
    fake.answer(
        "standardIntrospection",
        args -> {
          StandardIntrospectionResponse s = new StandardIntrospectionResponse();
          s.setAction(StandardIntrospectionResponse.Action.OK);
          s.setResponseContent("{\"active\":true}");
          return s;
        });
    Result denied =
        route(app, post("/api/introspection", Map.of("token", "t")).header("Authorization", basic("rs0", "bad")));
    assertEquals(401, denied.status());
    assertEquals(0, fake.count("standardIntrospection"));

    Result ok =
        route(app, post("/api/introspection", Map.of("token", "t")).header("Authorization", basic("rs0", "rs0-secret")));
    assertEquals(200, ok.status());
    assertTrue(contentAsString(ok).contains("active"));
  }

  @Test
  public void userinfoRequiresTokenAndReturnsUserClaims() {
    Result missing = route(app, get("/api/userinfo"));
    assertEquals(400, missing.status());
    assertTrue(missing.header("WWW-Authenticate").orElse("").contains("invalid_token"));

    fake.answer(
            "userinfo",
            args -> {
              UserInfoResponse u = new UserInfoResponse();
              u.setAction(UserInfoResponse.Action.OK);
              u.setSubject("1001");
              u.setToken("at");
              u.setClaims(new String[] {"name", "email"});
              return u;
            })
        .answer(
            "userinfoIssue",
            args -> {
              UserInfoIssueResponse i = new UserInfoIssueResponse();
              i.setAction(UserInfoIssueResponse.Action.JSON);
              i.setResponseContent("{\"sub\":\"1001\"}");
              return i;
            });
    Result r = route(app, get("/api/userinfo").header("Authorization", "Bearer at"));
    assertEquals(200, r.status());
    UserInfoIssueRequest issue = fake.lastRequest("userinfoIssue");
    assertTrue(issue.getClaims().contains("john@example.com"));
  }

  @Test
  public void cibaUnknownUserIsRejected() {
    fake.answer(
            "backchannelAuthentication",
            args -> {
              BackchannelAuthenticationResponse b = new BackchannelAuthenticationResponse();
              b.setAction(BackchannelAuthenticationResponse.Action.USER_IDENTIFICATION);
              b.setTicket("cib");
              b.setHintType(UserIdentificationHintType.LOGIN_HINT);
              b.setHint("nobody@example.com");
              return b;
            })
        .answer(
            "backchannelAuthenticationFail",
            args -> {
              BackchannelAuthenticationFailResponse f = new BackchannelAuthenticationFailResponse();
              f.setAction(BackchannelAuthenticationFailResponse.Action.BAD_REQUEST);
              f.setResponseContent("{\"error\":\"unknown_user_id\"}");
              return f;
            });
    Result r = route(app, post("/api/backchannel/authentication", Map.of("login_hint", "nobody@example.com")));
    assertEquals(400, r.status());
    BackchannelAuthenticationFailRequest fail = fake.lastRequest("backchannelAuthenticationFail");
    assertEquals(BackchannelAuthenticationFailRequest.Reason.UNKNOWN_USER_ID, fail.getReason());
  }

  @Test
  public void discoveryIsPublicAndCacheable() {
    fake.answer("getServiceConfiguration", args -> "{\"issuer\":\"https://as.example\"}");
    Result r = route(app, get("/.well-known/openid-configuration"));
    assertEquals(200, r.status());
    assertTrue(r.header("Cache-Control").orElse("").contains("max-age"));
    assertTrue(contentAsString(r).contains("issuer"));
  }
}

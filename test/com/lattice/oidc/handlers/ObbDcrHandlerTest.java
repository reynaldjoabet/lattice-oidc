package com.lattice.oidc.handlers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static play.test.Helpers.contentAsString;

import com.lattice.oidc.client.TestSettings;
import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.common.WebException;
import com.nimbusds.jose.JWSAlgorithm;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.After;
import org.junit.Test;

/** Open Banking Brasil dynamic client registration rules, against a local stand-in directory. */
public class ObbDcrHandlerTest {

  private final FakeObbDirectory directory = new FakeObbDirectory();
  private final ObbDcrHandler handler =
      new ObbDcrHandler(
          new LatticeConfig(
              TestSettings.config(Map.of("lattice.obb.directory-jwks-uri", directory.jwksUri))));

  @After
  public void stop() {
    directory.close();
  }

  /** Builds a request from a (possibly altered) statement and request, and expects a rejection. */
  private void rejected(
      String expectedError, Consumer<Map<String, Object>> ssChange, Consumer<Map<String, Object>> reqChange) {
    Map<String, Object> claims = new java.util.LinkedHashMap<>(FakeObbDirectory.claims());
    ssChange.accept(claims);
    Map<String, Object> req = new java.util.LinkedHashMap<>(FakeObbDirectory.request(directory.sign(claims)));
    reqChange.accept(req);
    rejected(expectedError, Jsons.write(req));
  }

  private void rejected(String expectedError, String body) {
    try {
      handler.process(body);
      fail("expected " + expectedError);
    } catch (WebException e) {
      String content = contentAsString(e.result());
      assertTrue(content, content.contains("\"" + expectedError + "\""));
    }
  }

  @Test
  public void detectsObbRequestsByTheDirectoryHostedJwks() {
    assertTrue(ObbDcrHandler.isObbRequest(directory.validRequestBody()));
    assertFalse(ObbDcrHandler.isObbRequest("{\"redirect_uris\":[\"https://a.example/cb\"]}"));
    assertFalse(ObbDcrHandler.isObbRequest("{\"software_statement\":\"not-a-jwt\"}"));
    assertFalse(ObbDcrHandler.isObbRequest("not json"));
  }

  @Test
  public void validRequestIsMergedWithTheFapiProfile() {
    Map<String, Object> merged = Jsons.readMap(handler.process(directory.validRequestBody()));
    assertEquals("PS256", merged.get("id_token_signed_response_alg"));
    assertEquals(Boolean.TRUE, merged.get("tls_client_certificate_bound_access_tokens"));
    assertEquals(Boolean.TRUE, merged.get("require_signed_request_object"));
    assertEquals("Example TPP", merged.get("client_name"));
    assertEquals(FakeObbDirectory.SOFTWARE_JWKS_URI, merged.get("jwks_uri"));
    // No scope requested: every scope of the DADOS role.
    assertTrue(((String) merged.get("scope")).contains("accounts"));
    assertFalse(((String) merged.get("scope")).contains("payments"));
    assertFalse("the statement itself is not registered", merged.containsKey("software_statement"));
  }

  @Test
  public void statementSignedByAnotherKeyIsRejected() {
    try (FakeObbDirectory impostor = new FakeObbDirectory()) {
      rejected("invalid_software_statement", impostor.validRequestBody());
    }
  }

  @Test
  public void statementMustBePs256AndFresh() {
    Map<String, Object> claims = FakeObbDirectory.claims();
    rejected(
        "invalid_software_statement",
        Jsons.write(FakeObbDirectory.request(directory.sign(claims, JWSAlgorithm.RS256, new Date()))));
    Date stale = new Date(System.currentTimeMillis() - 10 * 60_000);
    rejected(
        "invalid_software_statement",
        Jsons.write(FakeObbDirectory.request(directory.sign(claims, JWSAlgorithm.PS256, stale))));
    Date future = new Date(System.currentTimeMillis() + 10 * 60_000);
    rejected(
        "invalid_software_statement",
        Jsons.write(FakeObbDirectory.request(directory.sign(claims, JWSAlgorithm.PS256, future))));
  }

  @Test
  public void requestMustAgreeWithTheStatement() {
    rejected("invalid_client_metadata", ss -> {}, req -> req.put("jwks_uri", "https://evil.example/jwks"));
    rejected(
        "invalid_redirect_uri",
        ss -> {},
        req -> req.put("redirect_uris", List.of("https://evil.example/cb")));
    rejected("invalid_client_metadata", ss -> {}, req -> req.put("jwks", Map.of("keys", List.of())));
  }

  @Test
  public void scopesAreLimitedByRoles() {
    rejected("invalid_client_metadata", ss -> {}, req -> req.put("scope", "openid payments"));
    rejected(
        "invalid_software_statement", ss -> ss.put("software_roles", List.of("ROOT")), req -> {});
  }

  @Test
  public void weakAlgorithmsAndAuthMethodsAreRejected() {
    rejected(
        "invalid_client_metadata",
        ss -> {},
        req -> req.put("token_endpoint_auth_method", "client_secret_basic"));
    rejected(
        "invalid_client_metadata", ss -> {}, req -> req.put("id_token_signed_response_alg", "RS256"));
    rejected(
        "invalid_client_metadata", ss -> {}, req -> req.put("request_object_encryption_alg", "RSA1_5"));
    rejected(
        "invalid_client_metadata", ss -> {}, req -> req.put("tls_client_auth_san_dns", "tpp.example"));
  }

  @Test
  public void malformedBodiesAreRejected() {
    rejected("invalid_request", "[]");
    rejected("invalid_request", "{}");
    rejected("invalid_software_statement", "{\"software_statement\":\"not-a-jwt\"}");
  }
}

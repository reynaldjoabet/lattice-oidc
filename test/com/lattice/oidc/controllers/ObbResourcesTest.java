package com.lattice.oidc.controllers;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.route;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static play.test.Helpers.contentAsString;

import com.authlete.common.dto.IntrospectionRequest;
import com.authlete.common.dto.IntrospectionResponse;
import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.common.Jsons;
import java.util.Map;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.Application;
import play.mvc.Http;
import play.mvc.Result;
import play.test.Helpers;

/**
 * Open Banking Brasil resource APIs: consents belong to the client that created them, data APIs
 * need a consent-bound token, and every response carries an {@code x-fapi-interaction-id}.
 */
public class ObbResourcesTest {

  private static final String IID = "8c6b3a8e-1d2f-4b6a-9e3c-0f1e2d3c4b5a";
  private static final String CONSENT_BODY =
      "{\"data\":{\"permissions\":[\"ACCOUNTS_READ\"],\"expirationDateTime\":\"2030-01-01T00:00:00Z\"}}";

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private Application app;

  @Before
  public void start() {
    tokenOf(42L, "consents");
    app = app(fake);
    Helpers.start(app);
  }

  @After
  public void stop() {
    Helpers.stop(app);
  }

  /** Every access token introspects as belonging to {@code clientId} with {@code scopes}. */
  private void tokenOf(long clientId, String... scopes) {
    fake.answer(
        "introspection",
        args -> {
          IntrospectionResponse r = new IntrospectionResponse();
          r.setAction(IntrospectionResponse.Action.OK);
          r.setClientId(clientId);
          r.setScopes(scopes);
          return r;
        });
  }

  private static Http.RequestBuilder request(String method, String uri) {
    return new Http.RequestBuilder()
        .method(method)
        .uri(uri)
        .header("Authorization", "Bearer at-1")
        .header("x-fapi-interaction-id", IID);
  }

  private String createConsent() {
    Result r =
        route(
            app,
            request("POST", "/api/obb/consents")
                .bodyText(CONSENT_BODY)
                .header("Content-Type", "application/json"));
    assertEquals(201, r.status());
    @SuppressWarnings("unchecked")
    Map<String, Object> data = (Map<String, Object>) Jsons.readMap(contentAsString(r)).get("data");
    return (String) data.get("consentId");
  }

  @Test
  public void consentIsCreatedAndReadableByItsClient() {
    String id = createConsent();
    Result r = route(app, request("GET", "/api/obb/consents/" + id));
    assertEquals(200, r.status());
    assertTrue(contentAsString(r).contains("ACCOUNTS_READ"));
    assertEquals(IID, r.header("x-fapi-interaction-id").orElse(null));
    IntrospectionRequest sent = fake.lastRequest("introspection");
    assertArrayEquals(new String[] {"consents"}, sent.getScopes());
  }

  @Test
  public void anotherClientCannotReadOrDeleteTheConsent() {
    String id = createConsent();
    tokenOf(99L, "consents");
    assertEquals(403, route(app, request("GET", "/api/obb/consents/" + id)).status());
    assertEquals(403, route(app, request("DELETE", "/api/obb/consents/" + id)).status());

    tokenOf(42L, "consents");
    assertEquals("still there", 200, route(app, request("GET", "/api/obb/consents/" + id)).status());
  }

  @Test
  public void ownerCanDeleteTheConsent() {
    String id = createConsent();
    assertEquals(204, route(app, request("DELETE", "/api/obb/consents/" + id)).status());
    assertEquals(404, route(app, request("GET", "/api/obb/consents/" + id)).status());
  }

  @Test
  public void consentWithoutDataIsRejected() {
    Result r =
        route(app, request("POST", "/api/obb/consents").bodyText("{}").header("Content-Type", "application/json"));
    assertEquals(400, r.status());
  }

  @Test
  public void accountsNeedAConsentBoundToken() {
    tokenOf(42L, "openid", "accounts");
    Result withoutConsent = route(app, request("GET", "/api/obb/accounts"));
    assertEquals(403, withoutConsent.status());
    assertTrue(contentAsString(withoutConsent).contains("consent scope"));

    tokenOf(42L, "openid", "accounts", "consent:urn:lattice:abc");
    Result ok = route(app, request("GET", "/api/obb/accounts"));
    assertEquals(200, ok.status());
    assertTrue(contentAsString(ok).contains("accountId"));
    assertArrayEquals(new String[] {"accounts"}, ((IntrospectionRequest) fake.lastRequest("introspection")).getScopes());
  }

  @Test
  public void fapi2BaselineAccountsRequireTheirOwnScope() {
    tokenOf(42L, "consent:urn:lattice:abc");
    route(app, request("GET", "/api/obb/fapi2base-accounts"));
    assertArrayEquals(
        new String[] {"fapi2base-accounts"}, ((IntrospectionRequest) fake.lastRequest("introspection")).getScopes());
  }

  @Test
  public void rejectedTokensKeepTheInteractionId() {
    fake.answer(
        "introspection",
        args -> {
          IntrospectionResponse r = new IntrospectionResponse();
          r.setAction(IntrospectionResponse.Action.UNAUTHORIZED);
          r.setResultMessage("expired");
          return r;
        });
    Result r = route(app, request("GET", "/api/obb/resources"));
    assertEquals(401, r.status());
    assertEquals(IID, r.header("x-fapi-interaction-id").orElse(null));
  }

  @Test
  public void interactionIdIsGeneratedWhenAbsentAndMalformedOnesAreRejected() {
    tokenOf(42L, "resources", "consent:urn:lattice:abc");
    Result generated =
        route(app, new Http.RequestBuilder().method("GET").uri("/api/obb/resources").header("Authorization", "Bearer at-1"));
    assertEquals(200, generated.status());
    assertTrue(generated.header("x-fapi-interaction-id").isPresent());

    Result malformed =
        route(
            app,
            new Http.RequestBuilder()
                .method("GET")
                .uri("/api/obb/resources")
                .header("Authorization", "Bearer at-1")
                .header("x-fapi-interaction-id", "not-a-uuid"));
    assertEquals(400, malformed.status());
  }

  @Test
  public void apisAreHiddenWhenObbIsDisabled() {
    Helpers.stop(app);
    app = app(fake, Map.of("lattice.obb.enabled", false));
    Helpers.start(app);
    assertEquals(404, route(app, request("GET", "/api/obb/accounts")).status());
    assertEquals(0, fake.count("introspection"));
  }
}

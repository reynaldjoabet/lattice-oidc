package com.lattice.oidc.controllers;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.get;
import static com.lattice.oidc.OidcTestSupport.route;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static play.test.Helpers.contentAsString;

import com.authlete.common.dto.Client;
import com.authlete.common.dto.FederationConfigurationResponse;
import com.authlete.common.dto.FederationRegistrationRequest;
import com.authlete.common.dto.FederationRegistrationResponse;
import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.stores.AuditEventStore;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.Application;
import play.mvc.Http;
import play.mvc.Result;
import play.test.Helpers;

/** OpenID Federation 1.0: the entity configuration and explicit client registration (§12.2). */
public class FederationTest {

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

  /** A compact JWS with the given {@code typ}; the signature isn't checked by Lattice (Authlete made it). */
  private static String jwt(String typ) {
    Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
    String header = b64.encodeToString(("{\"alg\":\"ES256\",\"typ\":\"" + typ + "\"}").getBytes(StandardCharsets.UTF_8));
    String payload = b64.encodeToString("{\"iss\":\"https://op.example\",\"sub\":\"https://rp.example\"}".getBytes(StandardCharsets.UTF_8));
    return header + "." + payload + "." + b64.encodeToString(new byte[64]);
  }

  private static Http.RequestBuilder register(String contentType, String body) {
    Http.RequestBuilder b = new Http.RequestBuilder().method("POST").uri("/api/federation/register");
    if (body != null) {
      b.bodyText(body);
    }
    return b.header("Content-Type", contentType);
  }

  private void authleteRegisters(String responseJwt) {
    fake.answer(
        "federationRegistration",
        args -> {
          FederationRegistrationResponse r = new FederationRegistrationResponse();
          r.setAction(FederationRegistrationResponse.Action.OK);
          r.setResponseContent(responseJwt);
          Client client = new Client();
          client.setClientId(4242L);
          client.setEntityId(URI.create("https://rp.example"));
          client.setTrustAnchorId(URI.create("https://ta.example"));
          r.setClient(client);
          return r;
        });
  }

  private List<Map<String, Object>> events(String event) {
    return app.injector()
        .instanceOf(AuditEventStore.class)
        .search(new AuditEventStore.Query(Optional.of(event), Optional.empty(), Optional.empty(), 100));
  }

  @Test
  public void theEntityConfigurationIsServedAsAnEntityStatement() {
    fake.answer(
        "federationConfiguration",
        args -> {
          FederationConfigurationResponse r = new FederationConfigurationResponse();
          r.setAction(FederationConfigurationResponse.Action.OK);
          r.setResponseContent(jwt("entity-statement+jwt"));
          return r;
        });
    Result result = route(app, get("/.well-known/openid-federation"));
    assertEquals(200, result.status());
    assertEquals("application/entity-statement+jwt", result.contentType().orElse(""));
  }

  @Test
  public void noEntityConfigurationIsA404() {
    fake.answer(
        "federationConfiguration",
        args -> {
          FederationConfigurationResponse r = new FederationConfigurationResponse();
          r.setAction(FederationConfigurationResponse.Action.NOT_FOUND);
          r.setResponseContent("{\"error\":\"not_found\",\"error_description\":\"Federation is not enabled.\"}");
          return r;
        });
    assertEquals(404, route(app, get("/.well-known/openid-federation")).status());
  }

  @Test
  public void anEntityConfigurationIsPassedToAuthlete() {
    authleteRegisters(jwt("explicit-registration-response+jwt"));
    String rpConfiguration = jwt("entity-statement+jwt");
    Result result = route(app, register("application/entity-statement+jwt", rpConfiguration));
    assertEquals(200, result.status());
    FederationRegistrationRequest sent = fake.lastRequest("federationRegistration");
    assertEquals(rpConfiguration, sent.getEntityConfiguration());
    assertNull(sent.getTrustChain());
  }

  @Test
  public void aTrustChainIsPassedToAuthlete() {
    authleteRegisters(jwt("explicit-registration-response+jwt"));
    String chain = "[\"" + jwt("entity-statement+jwt") + "\",\"" + jwt("entity-statement+jwt") + "\"]";
    Result result = route(app, register("application/trust-chain+json", chain));
    assertEquals(200, result.status());
    FederationRegistrationRequest sent = fake.lastRequest("federationRegistration");
    assertEquals(chain, sent.getTrustChain());
    assertNull(sent.getEntityConfiguration());
  }

  @Test
  public void theResponseUsesTheFinalSpecificationsMediaType() {
    authleteRegisters(jwt("explicit-registration-response+jwt"));
    Result result = route(app, register("application/entity-statement+jwt", jwt("entity-statement+jwt")));
    assertEquals("application/explicit-registration-response+jwt", result.contentType().orElse(""));
  }

  @Test
  public void aResponseTypedAsInTheDraftsIsServedAsAnEntityStatement() {
    authleteRegisters(jwt("entity-statement+jwt"));
    Result result = route(app, register("application/entity-statement+jwt", jwt("entity-statement+jwt")));
    assertEquals(200, result.status());
    assertEquals("application/entity-statement+jwt", result.contentType().orElse(""));
  }

  @Test
  public void anUnreadableResponseIsStillServedAsAnEntityStatement() {
    assertEquals("application/entity-statement+jwt", FederationController.registrationResponseType("not a jwt"));
    assertEquals("application/entity-statement+jwt", FederationController.registrationResponseType(null));
  }

  @Test
  public void aRegistrationIsAudited() {
    authleteRegisters(jwt("explicit-registration-response+jwt"));
    route(app, register("application/entity-statement+jwt", jwt("entity-statement+jwt")));
    List<Map<String, Object>> registered = events("CLIENT_REGISTERED");
    assertEquals(1, registered.size());
    Map<String, Object> event = registered.get(0);
    assertEquals("federation", event.get("via"));
    assertEquals("https://rp.example", event.get("entity_id"));
    assertEquals("https://ta.example", event.get("trust_anchor"));
    assertEquals("4242", String.valueOf(event.get("client_id")));
  }

  @Test
  public void anotherContentTypeIsRefusedWithoutCallingAuthlete() {
    Result result = route(app, register("application/json", "{}"));
    assertEquals(415, result.status());
    assertTrue(contentAsString(result).contains("invalid_request"));
    assertEquals(0, fake.count("federationRegistration"));
  }

  @Test
  public void anEmptyBodyIsRefusedWithoutCallingAuthlete() {
    Result result = route(app, register("application/entity-statement+jwt", "  "));
    assertEquals(400, result.status());
    assertTrue(contentAsString(result).contains("invalid_request"));
    assertEquals(0, fake.count("federationRegistration"));
  }

  @Test
  public void authletesRejectionIsPassedOnAsJsonAndNotAudited() {
    fake.answer(
        "federationRegistration",
        args -> {
          FederationRegistrationResponse r = new FederationRegistrationResponse();
          r.setAction(FederationRegistrationResponse.Action.BAD_REQUEST);
          r.setResponseContent("{\"error\":\"invalid_trust_chain\",\"error_description\":\"No trust anchor.\"}");
          return r;
        });
    Result result = route(app, register("application/entity-statement+jwt", jwt("entity-statement+jwt")));
    assertEquals(400, result.status());
    assertTrue(result.contentType().orElse("").startsWith("application/json"));
    assertTrue(contentAsString(result).contains("invalid_trust_chain"));
    assertEquals(0, events("CLIENT_REGISTERED").size());
  }
}

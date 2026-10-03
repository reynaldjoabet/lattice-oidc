package com.lattice.oidc.controllers;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.route;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static play.test.Helpers.contentAsString;

import com.authlete.common.dto.Client;
import com.authlete.common.dto.ClientRegistrationRequest;
import com.authlete.common.dto.ClientRegistrationResponse;
import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.handlers.FakeObbDirectory;
import com.lattice.oidc.security.ObbTestPki;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.Application;
import play.mvc.Http;
import play.mvc.Result;
import play.test.Helpers;

/**
 * Dynamic client registration (RFC 7591/7592). Plain registrations are passed to Authlete
 * unchanged; Open Banking Brasil registrations and management calls on OBB clients need a client
 * certificate issued under the OBB root.
 */
public class ClientRegistrationTest {

  private static final String PLAIN = "{\"redirect_uris\":[\"https://client.example/cb\"]}";

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private final FakeObbDirectory directory = new FakeObbDirectory();
  private Application app;

  @Before
  public void start() {
    fake.answer("dynamicClientRegister", args -> response(ClientRegistrationResponse.Action.CREATED))
        .answer("dynamicClientGet", args -> response(ClientRegistrationResponse.Action.OK))
        .answer("dynamicClientDelete", args -> response(ClientRegistrationResponse.Action.DELETED))
        .answer("getClient", args -> new Client().setClientId(7L));
    app =
        app(
            fake,
            Map.of(
                "lattice.obb.enabled", true,
                "lattice.obb.root-certificates", List.of(ObbTestPki.rootFile()),
                "lattice.obb.directory-jwks-uri", directory.jwksUri,
                "lattice.mtls.trust-proxy-headers", true));
    Helpers.start(app);
  }

  @After
  public void stop() {
    Helpers.stop(app);
    directory.close();
  }

  private static ClientRegistrationResponse response(ClientRegistrationResponse.Action action) {
    ClientRegistrationResponse r = new ClientRegistrationResponse();
    r.setAction(action);
    r.setResponseContent("{\"client_id\":\"7\"}");
    return r;
  }

  private static Http.RequestBuilder request(String method, String uri, String body, String certPem) {
    Http.RequestBuilder b =
        new Http.RequestBuilder()
            .method(method)
            .uri(uri)
            .header("Authorization", "Bearer rat-123");
    if (body != null) {
      b.bodyText(body).header("Content-Type", "application/json");
    }
    if (certPem != null) {
      // As forwarded by a TLS-terminating proxy: URL-encoded PEM.
      b.header("X-Ssl-Cert", URLEncoder.encode(certPem, StandardCharsets.UTF_8).replace("+", "%20"));
    }
    return b;
  }

  private void obbClient() {
    fake.answer(
        "getClient",
        args -> new Client().setClientId(7L).setCustomMetadata("{\"software_roles\":[\"DADOS\"]}"));
  }

  @Test
  public void plainRegistrationIsPassedThroughWithTheInitialAccessToken() {
    Result r = route(app, request("POST", "/api/register", PLAIN, null));
    assertEquals(201, r.status());
    ClientRegistrationRequest sent = fake.lastRequest("dynamicClientRegister");
    assertEquals(PLAIN, sent.getJson());
    assertEquals("rat-123", sent.getToken());
  }

  @Test
  public void obbRegistrationWithoutCertificateIsRejected() {
    Result r = route(app, request("POST", "/api/register", directory.validRequestBody(), null));
    assertEquals(401, r.status());
    assertTrue(contentAsString(r).contains("invalid_client"));
    assertEquals(0, fake.count("dynamicClientRegister"));
  }

  @Test
  public void obbRegistrationWithCertificateFromAnotherRootIsRejected() {
    Result r =
        route(app, request("POST", "/api/register", directory.validRequestBody(), ObbTestPki.STRANGER));
    assertEquals(401, r.status());
    assertEquals(0, fake.count("dynamicClientRegister"));
  }

  @Test
  public void obbRegistrationWithValidCertificateRegistersTheFapiProfile() {
    Result r =
        route(app, request("POST", "/api/register", directory.validRequestBody(), ObbTestPki.LEAF));
    assertEquals(201, r.status());
    ClientRegistrationRequest sent = fake.lastRequest("dynamicClientRegister");
    Map<String, Object> json = Jsons.readMap(sent.getJson());
    assertEquals(Boolean.TRUE, json.get("tls_client_certificate_bound_access_tokens"));
    assertEquals("PS256", json.get("id_token_signed_response_alg"));
  }

  @Test
  public void anObbCertificateMakesTheRequestObbEvenWithoutAStatement() {
    Result r = route(app, request("POST", "/api/register", PLAIN, ObbTestPki.LEAF));
    assertEquals("OBB rules apply, so the missing software statement is an error", 400, r.status());
    assertEquals(0, fake.count("dynamicClientRegister"));
  }

  @Test
  public void managingAnObbClientRequiresItsCertificate() {
    obbClient();
    assertEquals(401, route(app, request("GET", "/api/register/7", null, null)).status());
    assertEquals(401, route(app, request("DELETE", "/api/register/7", null, ObbTestPki.STRANGER)).status());
    assertEquals(0, fake.count("dynamicClientGet") + fake.count("dynamicClientDelete"));

    assertEquals(200, route(app, request("GET", "/api/register/7", null, ObbTestPki.LEAF)).status());
    assertEquals(204, route(app, request("DELETE", "/api/register/7", null, ObbTestPki.LEAF)).status());
    ClientRegistrationRequest deleted = fake.lastRequest("dynamicClientDelete");
    assertEquals("7", deleted.getClientId());
    assertEquals("rat-123", deleted.getToken());
  }

  @Test
  public void managingAPlainClientNeedsNoCertificate() {
    assertEquals(200, route(app, request("GET", "/api/register/7", null, null)).status());
  }

  @Test
  public void certificateHeadersAreIgnoredUnlessTheProxyIsTrusted() {
    Helpers.stop(app);
    app =
        app(
            fake,
            Map.of(
                "lattice.obb.root-certificates", List.of(ObbTestPki.rootFile()),
                "lattice.obb.directory-jwks-uri", directory.jwksUri));
    Helpers.start(app);
    Result r =
        route(app, request("POST", "/api/register", directory.validRequestBody(), ObbTestPki.LEAF));
    assertEquals(401, r.status());
  }
}

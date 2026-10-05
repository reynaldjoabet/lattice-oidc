package com.lattice.oidc.controllers;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.get;
import static com.lattice.oidc.OidcTestSupport.post;
import static com.lattice.oidc.OidcTestSupport.route;
import static com.lattice.oidc.OidcTestSupport.withCsrf;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static play.test.Helpers.contentAsString;

import com.authlete.common.dto.Client;
import com.authlete.common.dto.ClientListResponse;
import com.authlete.common.dto.ClientSecretRefreshResponse;
import com.authlete.common.types.ClientAuthMethod;
import com.authlete.common.types.ClientType;
import com.authlete.common.types.GrantType;
import com.lattice.oidc.client.FakeAuthleteApi;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.Application;
import play.mvc.Result;
import play.test.Helpers;

/** Operator console: clients (list, edit, rotate secret, delete) and the security page. */
public class ConsoleTest {

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private Application app;

  private static Client notes() {
    Client client = new Client();
    client.setClientId(42L);
    client.setClientName("Acme Notes");
    client.setClientType(ClientType.CONFIDENTIAL);
    client.setTokenAuthMethod(ClientAuthMethod.CLIENT_SECRET_BASIC);
    client.setGrantTypes(new GrantType[] {GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN});
    client.setRedirectUris(new String[] {"https://notes.example/cb"});
    return client;
  }

  private static Client television() {
    Client client = new Client();
    client.setClientId(43L);
    client.setClientName("Living Room TV");
    client.setClientType(ClientType.PUBLIC);
    client.setGrantTypes(new GrantType[] {GrantType.DEVICE_CODE});
    client.setDynamicallyRegistered(true);
    return client;
  }

  @Before
  public void start() {
    fake.answer(
            "getClientList",
            args -> {
              ClientListResponse response = new ClientListResponse();
              response.setClients(new Client[] {notes(), television()});
              response.setTotalCount(2);
              return response;
            })
        .answer("getClient", args -> ((Long) args[0]) == 42L ? notes() : television())
        .answer("updateClient", args -> args[0])
        .answer("deleteClient", args -> null)
        .answer(
            "refreshClientSecret",
            args -> {
              ClientSecretRefreshResponse response = new ClientSecretRefreshResponse();
              response.setNewClientSecret("new-secret-value");
              return response;
            })
        .answer("getServiceConfiguration", args -> "{\"issuer\":\"https://lattice.example\",\"scopes_supported\":[\"openid\",\"profile\",\"email\"]}")
        .answer("getServiceJwks", args -> "{\"keys\":[]}");
    app = app(fake, Map.of("lattice.admin.login-ids", List.of("john")));
    Helpers.start(app);
  }

  @After
  public void stop() {
    Helpers.stop(app);
  }

  private Map<String, String> signIn(String loginId) {
    return route(app, withCsrf(post("/account/login", Map.of("loginId", loginId, "password", loginId, "next", "admin"))))
        .session()
        .data();
  }

  @Test
  public void onlyAdminsSeeClients() {
    Result anonymous = route(app, get("/admin/clients"));
    assertTrue(contentAsString(anonymous).contains("to open the operator console"));
    Result jane = route(app, get("/admin/clients").session(signIn("jane")));
    assertEquals(403, jane.status());
    assertEquals(0, fake.count("getClientList"));
  }

  @Test
  public void clientsAreListedAndFiltered() {
    Map<String, String> admin = signIn("john");
    String all = contentAsString(route(app, get("/admin/clients").session(admin)));
    assertTrue(all.contains("Acme Notes"));
    assertTrue(all.contains("Living Room TV"));
    assertTrue(all.contains("Web (confidential)"));
    assertTrue(all.contains("Device (public)"));
    assertTrue(all.contains("Dynamic (RFC 7591)"));

    String dynamic = contentAsString(route(app, get("/admin/clients?registration=dynamic").session(admin)));
    assertFalse(dynamic.contains("Acme Notes"));
    assertTrue(dynamic.contains("Living Room TV"));

    String searched = contentAsString(route(app, get("/admin/clients?query=notes").session(admin)));
    assertTrue(searched.contains("Acme Notes"));
    assertFalse(searched.contains("Living Room TV"));
  }

  private Map<String, String> validForm() {
    Map<String, String> form = new HashMap<>();
    form.put("name", "Acme Notes 2");
    form.put("website", "https://notes.example");
    form.put("redirectUris", "https://notes.example/cb\r\nhttp://localhost:3000/cb\r\ncom.example.notes:/cb");
    form.put("tokenAuthMethod", "private_key_jwt");
    form.put("pkceRequired", "true");
    form.put("scope", "openid");
    return form;
  }

  @Test
  public void editingAClientUpdatesItInAuthlete() {
    Result saved = route(app, withCsrf(post("/admin/clients/42", validForm())).session(signIn("john")));
    assertEquals(200, saved.status());
    assertTrue(contentAsString(saved).contains("Changes saved."));
    Client updated = fake.lastRequest("updateClient");
    assertEquals("Acme Notes 2", updated.getClientName());
    assertArrayEquals(
        new String[] {"https://notes.example/cb", "http://localhost:3000/cb", "com.example.notes:/cb"},
        updated.getRedirectUris());
    assertEquals(ClientAuthMethod.PRIVATE_KEY_JWT, updated.getTokenAuthMethod());
    assertTrue(updated.isPkceRequired());
    assertFalse(updated.isParRequired());
    assertTrue(updated.getExtension().isRequestableScopesEnabled());
    assertArrayEquals(new String[] {"openid"}, updated.getExtension().getRequestableScopes());
  }

  @Test
  public void unsafeRedirectUrisAreRefused() {
    Map<String, String> form = validForm();
    form.put("redirectUris", "http://notes.example/cb\nhttps://notes.example/cb#fragment");
    Result refused = route(app, withCsrf(post("/admin/clients/42", form)).session(signIn("john")));
    assertEquals(400, refused.status());
    assertTrue(contentAsString(refused).contains("http://notes.example/cb"));
    assertEquals(0, fake.count("updateClient"));
  }

  @Test
  public void rotatingTheSecretShowsItOnceWithoutCaching() {
    Result rotated = route(app, withCsrf(post("/admin/clients/42/secret", Map.of())).session(signIn("john")));
    assertEquals(200, rotated.status());
    assertEquals("no-store", rotated.header("Cache-Control").orElse(null));
    String html = contentAsString(rotated);
    assertTrue(html.contains("new-secret-value"));
    assertTrue("no grace period is promised", html.contains("has stopped working"));
  }

  @Test
  public void deletingAClientCallsAuthlete() {
    Result deleted = route(app, withCsrf(post("/admin/clients/43/delete", Map.of())).session(signIn("john")));
    assertEquals(303, deleted.status());
    assertEquals(43L, (long) (Long) fake.lastArgs.get("deleteClient")[0]);
  }

  @Test
  public void securityPageCountsFailedSignInsByIp() {
    for (int attempt = 0; attempt < 3; attempt++) {
      route(app, withCsrf(post("/account/login", Map.of("loginId", "jane", "password", "wrong", "next", "account"))));
    }
    route(app, withCsrf(post("/account/login", Map.of("loginId", "max", "password", "wrong", "next", "account"))));
    Result page = route(app, get("/admin/security").session(signIn("john")));
    assertEquals(200, page.status());
    String html = contentAsString(page);
    assertTrue(html.contains("Failed sign-ins"));
    assertTrue(html.contains("2 different"));
    assertTrue(html.contains("Passkey adoption"));
  }

  @Test
  public void theAuditLogCanBeFilteredByEventAndSubject() {
    route(app, withCsrf(post("/account/login", Map.of("loginId", "jane", "password", "wrong", "next", "account"))));
    Map<String, String> admin = signIn("john");

    String failures = contentAsString(route(app, get("/admin/audit?event=LOGIN_FAILED").session(admin)));
    assertTrue(failures.contains(">LOGIN_FAILED</span>"));
    assertFalse("filtered to the chosen event", failures.contains(">LOGIN_SUCCEEDED</span>"));

    String johns = contentAsString(route(app, get("/admin/audit?subject=1001").session(admin)));
    assertTrue(johns.contains(">LOGIN_SUCCEEDED</span>"));
    assertFalse(johns.contains(">LOGIN_FAILED</span>"));
    assertEquals(403, route(app, get("/admin/audit").session(signIn("jane"))).status());
  }
}

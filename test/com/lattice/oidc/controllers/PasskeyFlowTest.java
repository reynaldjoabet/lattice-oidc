package com.lattice.oidc.controllers;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.get;
import static com.lattice.oidc.OidcTestSupport.post;
import static com.lattice.oidc.OidcTestSupport.route;
import static com.lattice.oidc.OidcTestSupport.withCsrf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static play.test.Helpers.contentAsString;

import com.authlete.common.dto.AuthorizationFailRequest;
import com.authlete.common.dto.AuthorizationFailResponse;
import com.authlete.common.dto.AuthorizationResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.models.Passkey;
import com.lattice.oidc.security.Passkeys;
import com.lattice.oidc.stores.PasskeyStore;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.After;
import org.junit.Test;
import play.Application;
import play.libs.Json;
import play.mvc.Http;
import play.mvc.Result;
import play.test.Helpers;

/**
 * Passkeys around the protocol flows: the offer after a password sign-in, the WebAuthn options
 * endpoints, step-up for apps that require a phishing-resistant sign-in, and removing a passkey.
 * (A full WebAuthn ceremony needs an authenticator, so signatures are not exercised here.)
 */
public class PasskeyFlowTest {

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private Application app;

  private void start(Map<String, Object> config) {
    fake.answer("authorization", args -> AuthorizationFlowTest.interaction("ticket-1", null))
        .answer("authorizationIssue", args -> AuthorizationFlowTest.issued("https://client.example/cb?code=abc"))
        .answer(
            "authorizationFail",
            args -> {
              AuthorizationFailResponse response = new AuthorizationFailResponse();
              response.setAction(AuthorizationFailResponse.Action.LOCATION);
              response.setResponseContent("https://client.example/cb?error=unmet_authentication_requirements");
              return response;
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

  private Result authorizationPage() {
    Result page = route(app, withCsrf(get("/api/authorization?response_type=code&client_id=42&scope=openid")));
    assertEquals(200, page.status());
    return page;
  }

  private Result passwordSignIn(Result page) {
    return route(
        app,
        withCsrf(post("/api/authorization/decision", Map.of("ticket", "ticket-1", "loginId", "john", "password", "john", "login", "true")))
            .session(page.session().data()));
  }

  private Result accountSignIn() {
    Result login =
        route(app, withCsrf(post("/account/login", Map.of("loginId", "john", "password", "john", "next", "account"))));
    assertEquals(303, login.status());
    return login;
  }

  private static Http.RequestBuilder json(String uri, String body) {
    return new Http.RequestBuilder().method("POST").uri(uri).bodyJson(Json.parse(body));
  }

  private Passkey savePasskey() {
    PasskeyStore store = app.injector().instanceOf(PasskeyStore.class);
    Passkey passkey =
        new Passkey(
            "credential-1",
            "1001",
            store.userHandle("1001"),
            "cose-key",
            0L,
            "MacBook Pro",
            Instant.now(),
            Optional.empty(),
            true,
            Set.of("internal"));
    store.save(passkey);
    return passkey;
  }

  @Test
  public void passwordSignInOffersAPasskeyOnceThenContinuesToConsent() {
    start(Map.of());
    Result page = authorizationPage();
    Result offer = passwordSignIn(page);
    assertEquals(200, offer.status());
    String html = contentAsString(offer);
    assertTrue(html.contains("Sign in faster next time"));
    assertTrue(html.contains("data-passkey=\"register\""));
    assertTrue("the offer can be skipped", html.contains("/api/authorization/continue?ticket=ticket-1"));
    assertFalse("not offered again within the interval", app.injector().instanceOf(Passkeys.class).offerDue("1001"));

    Result consent = route(app, get("/api/authorization/continue?ticket=ticket-1").session(offer.session().data()));
    assertEquals(200, consent.status());
    assertTrue(contentAsString(consent).contains("name=\"authorized\""));
    assertEquals("nothing is issued by continuing", 0, fake.count("authorizationIssue"));
  }

  @Test
  public void registrationOptionsRequireASignedInUser() {
    start(Map.of());
    Result r = route(app, withCsrf(json("/passkeys/registration/options", "{\"next\":\"account\"}")));
    assertEquals(401, r.status());
    assertTrue(contentAsString(r).contains("\"error\""));
  }

  @Test
  public void registrationOptionsAskForADiscoverableVerifiedPasskey() {
    start(Map.of());
    Result login = accountSignIn();
    Result r =
        route(app, withCsrf(json("/passkeys/registration/options", "{\"next\":\"account\"}")).session(login.session().data()));
    assertEquals(200, r.status());
    assertEquals("no-store", r.header("Cache-Control").orElse(null));
    JsonNode body = Json.parse(contentAsString(r));
    assertFalse(body.get("ceremony").asText().isEmpty());
    JsonNode publicKey = body.get("options").get("publicKey");
    assertEquals("localhost", publicKey.get("rp").get("id").asText());
    assertFalse(publicKey.get("challenge").asText().isEmpty());
    assertEquals("required", publicKey.get("authenticatorSelection").get("residentKey").asText());
    assertEquals("required", publicKey.get("authenticatorSelection").get("userVerification").asText());
  }

  /**
   * The JSON endpoints accept only application/json, which another site can't send without a CORS
   * preflight (which fails). A cross-site form (text/plain) is refused.
   */
  @Test
  public void passkeyEndpointsRefuseCrossSiteFormBodies() {
    start(Map.of());
    Result login = accountSignIn();
    Http.RequestBuilder plain =
        new Http.RequestBuilder()
            .method("POST")
            .uri("/passkeys/registration/options")
            .bodyText("{\"next\":\"account\"}")
            .session(login.session().data());
    int status = route(app, plain).status();
    assertTrue("got " + status, status == 403 || status == 415);
  }

  @Test
  public void signInOptionsWorkWithoutAnAccountName() {
    start(Map.of());
    Result r = route(app, withCsrf(json("/passkeys/assertion/options", "{\"purpose\":\"signin\",\"next\":\"account\"}")));
    assertEquals(200, r.status());
    JsonNode publicKey = Json.parse(contentAsString(r)).get("options").get("publicKey");
    assertFalse(publicKey.get("challenge").asText().isEmpty());
    assertEquals("required", publicKey.get("userVerification").asText());
    assertTrue(
        "usernameless: no credential list to reveal accounts",
        !publicKey.has("allowCredentials") || publicKey.get("allowCredentials").isEmpty());
  }

  @Test
  public void unknownAssertionCeremoniesAreRejected() {
    start(Map.of());
    Result r = route(app, withCsrf(json("/passkeys/assertion", "{\"ceremony\":\"made-up\",\"credential\":{}}")));
    assertEquals(400, r.status());
    assertTrue(contentAsString(r).contains("/passkeys/failed"));
  }

  @Test
  public void failedPageOnlyLinksToKnownDestinations() {
    start(Map.of());
    Result r = route(app, get("/passkeys/failed?next=https://evil.example/"));
    assertEquals(200, r.status());
    String html = contentAsString(r);
    assertTrue(html.contains("href=\"/account\""));
    assertFalse(html.contains("evil.example"));
  }

  @Test
  public void appsRequiringPasskeysAskPasswordUsersToStepUp() {
    start(Map.of("lattice.passkeys.offer-interval", "0s"));
    fake.answer(
        "authorization",
        args -> {
          AuthorizationResponse response = AuthorizationFlowTest.interaction("ticket-1", null);
          response.setAcrs(new String[] {"phr"});
          response.setAcrEssential(true);
          return response;
        });
    savePasskey();
    Result consent = passwordSignIn(authorizationPage());
    Result decided =
        route(
            app,
            withCsrf(post("/api/authorization/decision", Map.of("ticket", "ticket-1", "authorized", "true")))
                .session(consent.session().data()));
    assertEquals(200, decided.status());
    String html = contentAsString(decided);
    assertTrue(html.contains("Verify it&#x27;s you") || html.contains("Verify it's you"));
    assertTrue(html.contains("data-passkey=\"stepup\""));
    assertEquals("nothing is issued before the step-up", 0, fake.count("authorizationIssue"));
  }

  @Test
  public void withoutAPasskeyTheRequiredSignInCannotBeMet() {
    start(Map.of("lattice.passkeys.offer-interval", "0s"));
    fake.answer(
        "authorization",
        args -> {
          AuthorizationResponse response = AuthorizationFlowTest.interaction("ticket-1", null);
          response.setAcrs(new String[] {"phr"});
          response.setAcrEssential(true);
          return response;
        });
    Result consent = passwordSignIn(authorizationPage());
    Result decided =
        route(
            app,
            withCsrf(post("/api/authorization/decision", Map.of("ticket", "ticket-1", "authorized", "true")))
                .session(consent.session().data()));
    assertEquals(302, decided.status());
    AuthorizationFailRequest fail = fake.lastRequest("authorizationFail");
    assertEquals(AuthorizationFailRequest.Reason.ACR_NOT_SATISFIED, fail.getReason());
    assertEquals(0, fake.count("authorizationIssue"));
  }

  @Test
  public void removingAPasskeyNeedsThePassword() {
    start(Map.of());
    Passkey passkey = savePasskey();
    Map<String, String> session = accountSignIn().session().data();
    PasskeyStore store = app.injector().instanceOf(PasskeyStore.class);

    Result account = route(app, get("/account").session(session));
    assertTrue(contentAsString(account).contains("MacBook Pro"));
    assertTrue(contentAsString(account).contains("/account/passkeys/credential-1/remove"));

    Result wrong =
        route(app, withCsrf(post("/account/passkeys/" + passkey.id() + "/remove", Map.of("password", "nope"))).session(session));
    assertEquals(401, wrong.status());
    assertTrue(store.byId(passkey.id()).isPresent());

    Result removed =
        route(app, withCsrf(post("/account/passkeys/" + passkey.id() + "/remove", Map.of("password", "john"))).session(session));
    assertEquals(303, removed.status());
    assertTrue(store.byId(passkey.id()).isEmpty());
  }
}

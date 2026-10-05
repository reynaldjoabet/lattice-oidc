package com.lattice.oidc.controllers;

import static com.lattice.oidc.OidcTestSupport.get;
import static com.lattice.oidc.OidcTestSupport.post;
import static com.lattice.oidc.OidcTestSupport.route;
import static com.lattice.oidc.OidcTestSupport.withCsrf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static play.inject.Bindings.bind;
import static play.test.Helpers.contentAsString;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.TokenFailResponse;
import com.authlete.common.dto.TokenResponse;
import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.common.Mailer;
import com.lattice.oidc.models.User;
import com.lattice.oidc.security.LoginService;
import com.lattice.oidc.stores.UserStore;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.After;
import org.junit.Test;
import play.Application;
import play.inject.guice.GuiceApplicationBuilder;
import play.mvc.Result;
import play.test.Helpers;

/** Required actions: terms, email verification, a new password, and where they're enforced. */
public class RequiredActionsTest {

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private final List<String> mail = new CopyOnWriteArrayList<>();
  private Application app;

  private void start(Map<String, Object> config) {
    fake.answer("authorization", args -> AuthorizationFlowTest.interaction("ticket-1", null));
    app =
        new GuiceApplicationBuilder()
            .configure(config)
            .configure("lattice.passkeys.offer-interval", "0s")
            .overrides(
                bind(AuthleteApi.class).toInstance(fake.api()),
                bind(Mailer.class).toInstance((to, subject, text) -> mail.add(text)))
            .build();
    Helpers.start(app);
  }

  @After
  public void stop() {
    if (app != null) {
      Helpers.stop(app);
    }
  }

  private Result signIn(String loginId, String password) {
    return route(app, withCsrf(post("/account/login", Map.of("loginId", loginId, "password", password, "next", "account"))));
  }

  @Test
  public void newTermsMustBeAcceptedBeforeTheAccountPage() {
    start(Map.of("lattice.required-actions.terms-version", "2026-10"));
    Result signedIn = signIn("john", "john");
    assertEquals("/account/actions", signedIn.redirectLocation().orElse(null));
    Map<String, String> session = signedIn.session().data();

    Result account = route(app, get("/account").session(session));
    assertEquals("the account page waits", 303, account.status());
    assertTrue(contentAsString(route(app, get("/account/actions?next=account").session(session))).contains("Our terms have changed"));

    Result accepted = route(app, withCsrf(post("/account/actions/terms", Map.of("accept", "true", "next", "account"))).session(session));
    assertEquals(303, accepted.status());
    assertEquals("/account", route(app, get("/account/actions?next=account").session(session)).redirectLocation().orElse(null));
    assertEquals(200, route(app, get("/account").session(session)).status());
  }

  @Test
  public void decliningTheTermsSignsOut() {
    start(Map.of("lattice.required-actions.terms-version", "2026-10"));
    Map<String, String> session = signIn("john", "john").session().data();
    Result declined = route(app, withCsrf(post("/account/actions/terms", Map.of("decline", "true", "next", "account"))).session(session));
    assertTrue(contentAsString(declined).contains("Signed out"));
    assertFalse(declined.session().get("session_id").isPresent());
  }

  @Test
  public void anEmailIsVerifiedByItsLink() {
    start(Map.of("lattice.required-actions.verify-email", true));
    Map<String, String> jane = signIn("jane", "jane").session().data();
    assertTrue(contentAsString(route(app, get("/account/actions?next=account").session(jane))).contains("Verify your email"));
    route(app, withCsrf(post("/account/actions/verify-email", Map.of("next", "account"))).session(jane));
    Matcher token = Pattern.compile("token=([A-Za-z0-9_-]+)").matcher(mail.get(mail.size() - 1));
    assertTrue(token.find());

    Result opened = route(app, get("/account/verify-email?token=" + token.group(1)));
    assertTrue("the link works without signing in", contentAsString(opened).contains("Email verified"));
    assertEquals(400, route(app, get("/account/verify-email?token=" + token.group(1))).status());
    assertEquals("/account", route(app, get("/account/actions?next=account").session(jane)).redirectLocation().orElse(null));
  }

  @Test
  public void aFlaggedAccountChoosesANewPassword() {
    start(Map.of());
    UserStore users = app.injector().instanceOf(UserStore.class);
    User john = users.byLoginId("john").orElseThrow();
    Map<String, Object> attributes = new HashMap<>(john.attributes());
    attributes.put("requiredActions", List.of("UPDATE_PASSWORD"));
    users.save(new User(john.getSubject(), john.loginId(), john.passwordHash(), john.claims(), attributes, john.verifiedClaims()));

    Map<String, String> session = signIn("john", "john").session().data();
    String strong = "correct horse battery";
    Result weak = route(app, withCsrf(post("/account/actions/password", Map.of("password", "short", "confirmation", "short", "next", "account"))).session(session));
    assertEquals(400, weak.status());
    Result saved = route(app, withCsrf(post("/account/actions/password", Map.of("password", strong, "confirmation", strong, "next", "account"))).session(session));
    assertEquals(303, saved.status());
    assertEquals(200, route(app, get("/account").session(session)).status());
    assertEquals(LoginService.Outcome.SUCCESS, app.injector().instanceOf(LoginService.class).authenticate("john", strong).outcome());
  }

  @Test
  public void theConsentPageWaitsForRequiredActions() {
    start(Map.of("lattice.required-actions.terms-version", "2026-10"));
    Result page = route(app, withCsrf(get("/api/authorization?response_type=code&client_id=42")));
    Result signedIn =
        route(
            app,
            withCsrf(post("/api/authorization/decision", Map.of("ticket", "ticket-1", "loginId", "john", "password", "john", "login", "true")))
                .session(page.session().data()));
    assertEquals("/account/actions?next=authz%3Aticket-1", signedIn.redirectLocation().orElse(null));
    Map<String, String> session = signedIn.session().data();
    route(app, withCsrf(post("/account/actions/terms", Map.of("accept", "true", "next", "authz:ticket-1"))).session(session));
    Result onward = route(app, get("/account/actions?next=authz:ticket-1").session(session));
    assertEquals("/api/authorization/continue?ticket=ticket-1", onward.redirectLocation().orElse(null));
    assertTrue(contentAsString(route(app, get(onward.redirectLocation().get()).session(session))).contains("name=\"authorized\""));
  }

  @Test
  public void thePasswordGrantRefusesAccountsThatNeedInteraction() {
    start(Map.of("lattice.required-actions.terms-version", "2026-10"));
    fake.answer(
            "token",
            args -> {
              TokenResponse response = new TokenResponse();
              response.setAction(TokenResponse.Action.PASSWORD);
              response.setTicket("token-ticket");
              response.setUsername("john");
              response.setPassword("john");
              return response;
            })
        .answer(
            "tokenFail",
            args -> {
              TokenFailResponse response = new TokenFailResponse();
              response.setAction(TokenFailResponse.Action.BAD_REQUEST);
              response.setResponseContent("{\"error\":\"invalid_grant\"}");
              return response;
            });
    Result token = route(app, post("/api/token", Map.of("grant_type", "password", "username", "john", "password", "john")));
    assertEquals(400, token.status());
    assertEquals(0, fake.count("tokenIssue"));
  }
}

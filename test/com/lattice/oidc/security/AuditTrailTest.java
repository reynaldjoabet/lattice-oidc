package com.lattice.oidc.security;

import static com.lattice.oidc.OidcTestSupport.get;
import static com.lattice.oidc.OidcTestSupport.post;
import static com.lattice.oidc.OidcTestSupport.route;
import static com.lattice.oidc.OidcTestSupport.withCsrf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static play.inject.Bindings.bind;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.AuthorizationIssueResponse;
import com.authlete.common.dto.AuthorizationResponse;
import com.authlete.common.dto.Client;
import com.lattice.oidc.client.FakeAuthleteApi;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.Test;
import play.Application;
import play.inject.guice.GuiceApplicationBuilder;
import play.mvc.Result;
import play.test.Helpers;

public class AuditTrailTest {

  private final List<Map<String, Object>> records = new CopyOnWriteArrayList<>();

  @Test
  public void recordsLoginFailureThenSuccessAndConsentWithoutSecrets() {
    FakeAuthleteApi fake =
        new FakeAuthleteApi()
            .answer(
                "authorization",
                args -> {
                  AuthorizationResponse r = new AuthorizationResponse();
                  r.setAction(AuthorizationResponse.Action.INTERACTION);
                  r.setTicket("t1");
                  Client c = new Client();
                  c.setClientId(42L);
                  r.setClient(c);
                  return r;
                })
            .answer(
                "authorizationIssue",
                args -> {
                  AuthorizationIssueResponse r = new AuthorizationIssueResponse();
                  r.setAction(AuthorizationIssueResponse.Action.LOCATION);
                  r.setResponseContent("https://client.example/cb?code=x");
                  return r;
                });
    Application app =
        new GuiceApplicationBuilder()
            .overrides(
                bind(AuthleteApi.class).toInstance(fake.api()),
                bind(AuditService.Sink.class).toInstance(records::add))
            .build();
    Helpers.running(
        app,
        () -> {
          Result page = route(app, withCsrf(get("/api/authorization")));
          route(
              app,
              withCsrf(
                      post(
                          "/api/authorization/decision",
                          Map.of("ticket", "t1", "loginId", "jane", "password", "nope", "authorized", "true")))
                  .session(page.session().data()));
          route(
              app,
              withCsrf(
                      post(
                          "/api/authorization/decision",
                          Map.of("ticket", "t1", "loginId", "jane", "password", "jane", "authorized", "true")))
                  .session(page.session().data()));
        });

    List<Object> events = records.stream().map(r -> r.get("event")).toList();
    assertEquals(List.of("LOGIN_FAILED", "LOGIN_SUCCEEDED", "CONSENT_GRANTED"), events);
    assertEquals("1002", records.get(1).get("subject"));
    assertEquals("42", records.get(2).get("client_id"));
    records.forEach(r -> assertFalse(r.toString().contains("nope")));
  }
}

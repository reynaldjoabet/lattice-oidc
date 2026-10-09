package com.lattice.oidc.controllers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static play.inject.Bindings.bind;
import static play.test.Helpers.GET;
import static play.test.Helpers.contentAsString;
import static play.test.Helpers.route;

import com.authlete.common.api.AuthleteApi;
import com.lattice.oidc.client.FakeAuthleteApi;
import org.junit.Test;
import play.Application;
import play.inject.guice.GuiceApplicationBuilder;
import play.mvc.Http;
import play.mvc.Result;
import play.test.Helpers;

public class HealthControllerTest {

  private static Application app(AuthleteApi api) {
    return new GuiceApplicationBuilder().overrides(bind(AuthleteApi.class).toInstance(api)).build();
  }

  private static Result get(Application app, String uri) {
    return route(app, new Http.RequestBuilder().method(GET).uri(uri));
  }

  @Test
  public void liveIsAlwaysUp() {
    Application app = new GuiceApplicationBuilder().build();
    Helpers.running(
        app,
        () -> {
          Result r = get(app, "/health/live");
          assertEquals(200, r.status());
          assertEquals("no-store", r.header("Cache-Control").orElse(null));
        });
  }

  @Test
  public void dependenciesUpWhenAuthleteAnswers() {
    Application app =
        app(new FakeAuthleteApi().answer("getServiceConfiguration", args -> "{}").api());
    Helpers.running(
        app,
        () -> {
          Result r = get(app, "/health/dependencies");
          assertEquals(200, r.status());
          assertTrue(contentAsString(r).contains("\"status\":\"UP\""));
          assertTrue(contentAsString(r).contains("\"authlete\""));
        });
  }

  @Test
  public void anAuthleteOutageShowsInDependenciesButKeepsReplicasReady() {
    Application app =
        app(
            new FakeAuthleteApi()
                .answer(
                    "getServiceConfiguration",
                    args -> {
                      throw FakeAuthleteApi.failure(503);
                    })
                .api());
    Helpers.running(
        app,
        () -> {
          Result r = get(app, "/health/dependencies");
          assertEquals(503, r.status());
          assertTrue(contentAsString(r).contains("unreachable"));
          assertEquals("a shared outage must not take every replica out", 200, get(app, "/health/ready").status());
        });
  }

  @Test
  public void missingCredentialsShowInDependencies() {
    Application app = new GuiceApplicationBuilder().build();
    Helpers.running(
        app,
        () -> {
          Result r = get(app, "/health/dependencies");
          assertEquals(503, r.status());
          assertTrue(contentAsString(r).contains("not configured"));
        });
  }

  @Test
  public void browsersGetAPageAndApiClientsJsonWhenAuthleteIsDown() {
    Application app =
        app(
            new FakeAuthleteApi()
                .answer(
                    "authorization",
                    args -> {
                      throw FakeAuthleteApi.failure(503);
                    })
                .api());
    Helpers.running(
        app,
        () -> {
          String uri = "/api/authorization?response_type=code&client_id=42";
          Result browser =
              route(app, new Http.RequestBuilder().method(GET).uri(uri).header("Accept", "text/html,application/xhtml+xml,*/*;q=0.8"));
          assertEquals(503, browser.status());
          assertEquals("text/html", browser.contentType().orElse(null));
          assertTrue(contentAsString(browser).contains("Temporarily unavailable"));
          assertEquals("30", browser.header("Retry-After").orElse(null));

          Result api = route(app, new Http.RequestBuilder().method(GET).uri(uri).header("Accept", "application/json"));
          assertEquals(503, api.status());
          assertEquals("application/json", api.contentType().orElse(null));
          assertTrue(contentAsString(api).contains("server_error"));
          assertEquals("30", api.header("Retry-After").orElse(null));
        });
  }
}

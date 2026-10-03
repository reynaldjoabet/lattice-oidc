package com.lattice.oidc.health;

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
  public void readyWhenAuthleteAnswers() {
    Application app =
        app(new FakeAuthleteApi().answer("getServiceConfiguration", args -> "{}").api());
    Helpers.running(
        app,
        () -> {
          Result r = get(app, "/health/ready");
          assertEquals(200, r.status());
          assertTrue(contentAsString(r).contains("\"status\":\"UP\""));
        });
  }

  @Test
  public void notReadyWhenAuthleteFails() {
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
          Result r = get(app, "/health/ready");
          assertEquals(503, r.status());
          assertTrue(contentAsString(r).contains("unreachable"));
        });
  }

  @Test
  public void notReadyWhenCredentialsAreMissing() {
    Application app = new GuiceApplicationBuilder().build();
    Helpers.running(
        app,
        () -> {
          Result r = get(app, "/health/ready");
          assertEquals(503, r.status());
          assertTrue(contentAsString(r).contains("not configured"));
        });
  }
}

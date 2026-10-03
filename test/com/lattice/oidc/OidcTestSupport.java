package com.lattice.oidc;

import static play.inject.Bindings.bind;

import com.authlete.common.api.AuthleteApi;
import com.lattice.oidc.client.FakeAuthleteApi;
import java.util.Map;
import play.Application;
import play.inject.guice.GuiceApplicationBuilder;
import play.mvc.Http;
import play.mvc.Result;
import play.test.Helpers;

/** Builds a test application whose Authlete API is a scripted fake. */
public final class OidcTestSupport {
  private OidcTestSupport() {}

  public static Application app(FakeAuthleteApi fake) {
    return app(fake, Map.of());
  }

  public static Application app(FakeAuthleteApi fake, Map<String, Object> config) {
    return new GuiceApplicationBuilder()
        .configure(config)
        .overrides(bind(AuthleteApi.class).toInstance(fake.api()))
        .build();
  }

  public static Http.RequestBuilder get(String uri) {
    return new Http.RequestBuilder().method("GET").uri(uri);
  }

  public static Http.RequestBuilder post(String uri, Map<String, String> form) {
    return new Http.RequestBuilder().method("POST").uri(uri).bodyForm(form);
  }

  /**
   * Makes a browser-form request pass the CSRF filter (bypass header) while still giving
   * templates a token to render.
   */
  public static Http.RequestBuilder withCsrf(Http.RequestBuilder builder) {
    return play.api.test.CSRFTokenHelper.addCSRFToken(builder.header("Csrf-Token", "nocheck"));
  }

  public static Result route(Application app, Http.RequestBuilder request) {
    return Helpers.route(app, request);
  }
}

package com.lattice.oidc.controllers;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.get;
import static com.lattice.oidc.OidcTestSupport.route;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static play.test.Helpers.contentAsString;

import com.lattice.oidc.client.FakeAuthleteApi;
import org.junit.Test;
import play.Application;
import play.mvc.Result;
import play.test.Helpers;

public class HomeControllerTest {

  @Test
  public void startPageIsAProperPageNotPlaysSample() {
    Application app = app(new FakeAuthleteApi());
    Helpers.running(
        app,
        () -> {
          Result r = route(app, get("/"));
          assertEquals(200, r.status());
          String html = contentAsString(r);
          assertTrue(html.contains("Lattice sign-in"));
          assertTrue(html.contains("noindex"));
          assertTrue(!html.contains("Welcome to Play"));
        });
  }
}

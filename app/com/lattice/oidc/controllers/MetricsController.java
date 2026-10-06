package com.lattice.oidc.controllers;

import com.lattice.oidc.metrics.Metrics;
import com.typesafe.config.Config;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import jakarta.inject.Inject;
import play.mvc.Controller;
import play.mvc.Http;
import play.mvc.Result;

/**
 * {@code GET /metrics}: Prometheus metrics. Off unless {@code lattice.metrics.enabled}; with {@code
 * lattice.metrics.token} set, scrapers must send {@code Authorization: Bearer <token>}. Either way,
 * keep it off the public internet: it reveals traffic and sign-in volumes.
 */
public final class MetricsController extends Controller {

  private final Metrics metrics;
  private final boolean enabled;
  private final String token;

  @Inject
  public MetricsController(Metrics metrics, Config config) {
    this.metrics = metrics;
    this.enabled = config.getBoolean("lattice.metrics.enabled");
    this.token = config.getString("lattice.metrics.token");
  }

  public Result scrape(Http.Request request) {
    if (!enabled) {
      return notFound();
    }
    if (!token.isEmpty()) {
      String presented = request.header("Authorization").orElse("");
      byte[] expected = ("Bearer " + token).getBytes(StandardCharsets.UTF_8);
      if (!MessageDigest.isEqual(expected, presented.getBytes(StandardCharsets.UTF_8))) {
        return unauthorized().withHeader("WWW-Authenticate", "Bearer");
      }
    }
    return ok(metrics.scrape())
        .as("text/plain; version=0.0.4; charset=utf-8")
        .withHeader(CACHE_CONTROL, "no-store");
  }
}

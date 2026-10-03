package com.lattice.oidc.filters;

import com.typesafe.config.Config;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.apache.pekko.stream.Materializer;
import play.mvc.Filter;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;

/**
 * HTTP Strict Transport Security (RFC 6797), enabled with {@code lattice.security.hsts.enabled}.
 * Plain-HTTP GET/HEAD requests are redirected to HTTPS (other methods are refused, since
 * redirecting a POST would leak its body over HTTP first); HTTPS responses carry the
 * {@code Strict-Transport-Security} header. Health probes are exempt so that orchestrators can
 * check the pod over plain HTTP.
 */
@Singleton
public final class HstsFilter extends Filter {

  private final boolean enabled;
  private final String headerValue;

  @Inject
  public HstsFilter(Materializer mat, Config config) {
    super(mat);
    this.enabled = config.getBoolean("lattice.security.hsts.enabled");
    this.headerValue =
        "max-age=" + config.getDuration("lattice.security.hsts.max-age").toSeconds() + "; includeSubDomains";
  }

  @Override
  public CompletionStage<Result> apply(
      Function<Http.RequestHeader, CompletionStage<Result>> next, Http.RequestHeader request) {
    if (!enabled || request.path().startsWith("/health/")) {
      return next.apply(request);
    }
    if (!request.secure()) {
      boolean safe = request.method().equals("GET") || request.method().equals("HEAD");
      return CompletableFuture.completedFuture(
          safe
              ? Results.movedPermanently("https://" + request.host() + request.uri())
              : Results.status(403, "HTTPS is required."));
    }
    return next.apply(request).thenApply(r -> r.withHeader("Strict-Transport-Security", headerValue));
  }
}

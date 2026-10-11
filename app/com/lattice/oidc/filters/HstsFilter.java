package com.lattice.oidc.filters;

import com.typesafe.config.Config;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.apache.pekko.util.ByteString;
import play.libs.streams.Accumulator;
import play.mvc.EssentialAction;
import play.mvc.EssentialFilter;
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
public final class HstsFilter extends EssentialFilter {

  private final boolean enabled;
  private final String headerValue;

  @Inject
  public HstsFilter(Config config) {
    this.enabled = config.getBoolean("lattice.security.hsts.enabled");
    this.headerValue =
        "max-age=" + config.getDuration("lattice.security.hsts.max-age").toSeconds() + "; includeSubDomains";
  }

  @Override
  public EssentialAction apply(EssentialAction next) {
    if (!enabled) {
      return next;
    }
    return EssentialAction.of(
        request -> {
          if (request.path().startsWith("/health/")) {
            return next.apply(request);
          }
          if (!request.secure()) {
            boolean safe = request.method().equals("GET") || request.method().equals("HEAD");
            // Answered without reading the body: a POST over plain HTTP is refused, not redirected.
            return Accumulator.<ByteString, Result>done(
                safe
                    ? Results.movedPermanently("https://" + request.host() + request.uri())
                    : Results.status(403, "HTTPS is required."));
          }
          Accumulator<ByteString, Result> action = next.apply(request);
          return action.map(r -> r.withHeader("Strict-Transport-Security", headerValue), FilterSupport.DIRECT);
        });
  }
}

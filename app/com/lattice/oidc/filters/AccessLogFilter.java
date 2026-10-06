package com.lattice.oidc.filters;

import com.lattice.oidc.metrics.Metrics;
import java.time.Duration;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.apache.pekko.stream.Materializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.mvc.Filter;
import play.mvc.Http;
import play.mvc.Result;
import play.routing.Router;

/**
 * Access log on the {@code access} logger: method, path, status, latency, request id and client
 * address. The query string is deliberately never logged: on an OpenID Provider it can carry
 * authorization codes, {@code login_hint}, {@code id_token_hint} and other sensitive values. The
 * client address is Play's resolved {@code remoteAddress}, which only honours forwarding headers
 * from {@code play.http.forwarded.trustedProxies}. Each request is also counted in the metrics, by
 * route pattern (never the raw path, which may contain identifiers).
 */
@Singleton
public final class AccessLogFilter extends Filter {

  private static final Logger ACCESS = LoggerFactory.getLogger("access");

  private final Metrics metrics;

  @Inject
  public AccessLogFilter(Materializer materializer, Metrics metrics) {
    super(materializer);
    this.metrics = metrics;
  }

  @Override
  public CompletionStage<Result> apply(
      Function<Http.RequestHeader, CompletionStage<Result>> next, Http.RequestHeader request) {
    String path = request.path();
    if (path.startsWith("/health/") || path.startsWith("/assets/") || path.equals("/metrics")) {
      return next.apply(request);
    }
    long start = System.nanoTime();
    return next.apply(request)
        .thenApply(
            result -> {
              long elapsed = System.nanoTime() - start;
              String route =
                  request.attrs().getOptional(Router.Attrs.HANDLER_DEF).map(handler -> handler.path()).orElse("unmatched");
              metrics.httpRequest(request.method(), route, result.status(), Duration.ofNanos(elapsed));
              ACCESS.info(
                  "{} {} {} {}ms rid={} ip={}",
                  request.method(),
                  path,
                  result.status(),
                  elapsed / 1_000_000,
                  RequestIdFilter.of(request),
                  request.remoteAddress());
              return result;
            });
  }
}

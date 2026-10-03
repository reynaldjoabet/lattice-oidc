package com.lattice.oidc.filters;

import java.util.concurrent.CompletionStage;
import java.util.function.Function;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.apache.pekko.stream.Materializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.mvc.Filter;
import play.mvc.Http;
import play.mvc.Result;

/**
 * Access log on the {@code access} logger: method, path, status, latency, request id and client
 * address. The query string is deliberately never logged: on an OpenID Provider it can carry
 * authorization codes, {@code login_hint}, {@code id_token_hint} and other sensitive values. The
 * client address is Play's resolved {@code remoteAddress}, which only honours forwarding headers
 * from {@code play.http.forwarded.trustedProxies}.
 */
@Singleton
public final class AccessLogFilter extends Filter {

  private static final Logger ACCESS = LoggerFactory.getLogger("access");

  @Inject
  public AccessLogFilter(Materializer materializer) {
    super(materializer);
  }

  @Override
  public CompletionStage<Result> apply(
      Function<Http.RequestHeader, CompletionStage<Result>> next, Http.RequestHeader request) {
    String path = request.path();
    if (path.startsWith("/health/") || path.startsWith("/assets/")) {
      return next.apply(request);
    }
    long start = System.nanoTime();
    return next.apply(request)
        .thenApply(
            result -> {
              ACCESS.info(
                  "{} {} {} {}ms rid={} ip={}",
                  request.method(),
                  path,
                  result.status(),
                  (System.nanoTime() - start) / 1_000_000,
                  RequestIdFilter.of(request),
                  request.remoteAddress());
              return result;
            });
  }
}

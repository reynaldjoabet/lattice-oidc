package com.lattice.oidc.filters;

import com.lattice.oidc.common.Ids;
import java.util.regex.Pattern;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.apache.pekko.util.ByteString;
import play.libs.typedmap.TypedKey;
import play.libs.streams.Accumulator;
import play.mvc.EssentialAction;
import play.mvc.EssentialFilter;
import play.mvc.Http;
import play.mvc.Result;

/**
 * Assigns every request a correlation id: a well-formed incoming {@code X-Request-ID} (set by a
 * load balancer or the caller) is kept, otherwise one is generated. The id is stored as a request
 * attribute for logging/auditing and echoed in the response.
 *
 * <p>Request attributes are used instead of a ThreadLocal/MDC because request processing hops
 * between thread pools (the Authlete dispatcher), where thread-bound context would be lost.
 */
@Singleton
public final class RequestIdFilter extends EssentialFilter {

  public static final String HEADER = "X-Request-ID";
  public static final TypedKey<String> REQUEST_ID = TypedKey.create("requestId");

  /** Accept only short, log-safe ids so a client cannot inject content into logs. */
  private static final Pattern VALID = Pattern.compile("[A-Za-z0-9._:-]{1,64}");

  @Inject
  public RequestIdFilter() {}

  public static String of(Http.RequestHeader request) {
    return request.attrs().getOptional(REQUEST_ID).orElse("-");
  }

  @Override
  public EssentialAction apply(EssentialAction next) {
    return EssentialAction.of(
        request -> {
          String id =
              request.header(HEADER).filter(v -> VALID.matcher(v).matches()).orElseGet(Ids::timeOrdered);
          Accumulator<ByteString, Result> action = next.apply(request.addAttr(REQUEST_ID, id));
          return action.map(r -> r.withHeader(HEADER, id), FilterSupport.DIRECT);
        });
  }
}

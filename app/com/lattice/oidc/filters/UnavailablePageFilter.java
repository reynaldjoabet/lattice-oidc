package com.lattice.oidc.filters;

import com.lattice.oidc.controllers.Pages;
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
 * When Authlete can't be reached, browsers get Lattice's "temporarily unavailable" page instead of
 * the JSON error that API clients get. Controllers mark such responses with {@link #UNAVAILABLE};
 * this filter swaps the body for the page when the request asks for HTML, keeping the 503 status
 * and the {@code Retry-After} header.
 */
@Singleton
public final class UnavailablePageFilter extends EssentialFilter {

  /** Set on a response whose request failed because a service Lattice depends on didn't answer. */
  public static final TypedKey<Boolean> UNAVAILABLE = TypedKey.create("unavailable");

  @Inject
  public UnavailablePageFilter() {}

  @Override
  public EssentialAction apply(EssentialAction next) {
    return EssentialAction.of(
        request -> {
          Accumulator<ByteString, Result> action = next.apply(request);
          return action.map(
              result -> {
                if (!result.attrs().containsKey(UNAVAILABLE) || !wantsHtml(request)) {
                  return result;
                }
                Result page =
                    Pages.message(
                        request.withBody(new Http.RequestBody(null)),
                        result.status(),
                        "Temporarily unavailable",
                        "Signing in is temporarily unavailable. Please try again in a minute.");
                return result.header("Retry-After").map(value -> page.withHeader("Retry-After", value)).orElse(page);
              },
              FilterSupport.DIRECT);
        });
  }

  /** Browsers name text/html; API clients ask for JSON or send "* / *" (curl's default). */
  private static boolean wantsHtml(Http.RequestHeader request) {
    return request.header("Accept").map(accept -> accept.contains("text/html")).orElse(false);
  }
}

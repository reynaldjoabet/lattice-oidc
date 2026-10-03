package com.lattice.oidc.common;

import com.lattice.oidc.filters.RequestIdFilter;
import com.typesafe.config.Config;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.Environment;
import play.api.OptionalSourceMapper;
import play.api.UsefulException;
import play.api.routing.Router;
import play.http.DefaultHttpErrorHandler;
import play.mvc.Http;
import play.mvc.Result;

/**
 * Error responses for failures that happen outside controllers: unknown routes, unparsable bodies,
 * CSRF rejections and uncaught exceptions.
 *
 * <p>Protocol endpoints get OAuth-style JSON ({@code error}, {@code error_description}); the pages
 * end-users see in a browser (consent, device verification, logout, ...) get a minimal HTML page. Neither ever contains
 * stack traces or exception messages: server errors are logged with an incident id that is
 * returned to the caller for correlation.
 */
@Singleton
public final class ErrorHandler extends DefaultHttpErrorHandler {

  private static final Logger LOG = LoggerFactory.getLogger(ErrorHandler.class);

  @Inject
  public ErrorHandler(
      Config config,
      Environment environment,
      OptionalSourceMapper sourceMapper,
      Provider<Router> routes) {
    super(config, environment, sourceMapper, routes);
  }

  @Override
  public CompletionStage<Result> onClientError(
      Http.RequestHeader request, int statusCode, String message) {
    String error =
        switch (statusCode) {
          case 401 -> "invalid_client";
          case 403 -> "access_denied";
          case 404 -> "not_found";
          case 405 -> "method_not_allowed";
          default -> "invalid_request";
        };
    String description =
        switch (statusCode) {
          case 403 -> "The request was rejected (missing or invalid CSRF token, or a disallowed host).";
          case 404 -> "No such endpoint.";
          case 405 -> "The HTTP method is not allowed for this endpoint.";
          case 413 -> "The request body is too large.";
          case 415 -> "Unsupported content type.";
          default -> "The request is malformed.";
        };
    LOG.debug("Client error {} on {} {}: {}", statusCode, request.method(), request.path(), message);
    return CompletableFuture.completedFuture(
        respond(request, statusCode, error, description, RequestIdFilter.of(request)));
  }

  @Override
  public CompletionStage<Result> onServerError(Http.RequestHeader request, Throwable exception) {
    // WebExceptions that escape a controller still carry their intended response.
    for (Throwable t = exception; t != null; t = t.getCause()) {
      if (t instanceof WebException web) {
        return CompletableFuture.completedFuture(web.result());
      }
    }
    return super.onServerError(request, exception);
  }

  @Override
  protected CompletionStage<Result> onProdServerError(
      Http.RequestHeader request, UsefulException exception) {
    return CompletableFuture.completedFuture(serverError(request, exception));
  }

  @Override
  protected CompletionStage<Result> onDevServerError(
      Http.RequestHeader request, UsefulException exception) {
    return CompletableFuture.completedFuture(serverError(request, exception));
  }

  private static Result serverError(Http.RequestHeader request, UsefulException exception) {
    // DefaultHttpErrorHandler has already logged the exception together with this id.
    return respond(
        request,
        500,
        "server_error",
        "An unexpected error occurred. Incident id: " + exception.id + ".",
        exception.id);
  }

  private static Result respond(
      Http.RequestHeader request, int status, String error, String description, String reference) {
    if (isBrowserPage(request.path())) {
      return Responses.of(
          status,
          views.html.oidc.error.render(status, description, reference, request).body(),
          Responses.HTML,
          null);
    }
    return Responses.json(
        status, Jsons.write(Map.of("error", error, "error_description", description)));
  }

  /**
   * Pages rendered for end-users in a browser. Everything else (protocol and resource endpoints,
   * metadata, unknown paths) gets JSON, whatever the {@code Accept} header says: many OAuth clients
   * send {@code Accept: *}{@code /*}.
   */
  private static boolean isBrowserPage(String path) {
    return BROWSER_PAGES.contains(path) || path.startsWith("/api/federation/");
  }

  private static final java.util.Set<String> BROWSER_PAGES =
      java.util.Set.of(
          "/",
          "/api/authorization",
          "/api/authorization/decision",
          "/api/device/verification",
          "/api/device/complete",
          "/api/offer/issue",
          "/api/logout",
          "/api/logout/confirm");
}

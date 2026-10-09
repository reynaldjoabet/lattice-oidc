package com.lattice.oidc.common;

import java.util.Map;
import play.mvc.Result;
import play.mvc.Results;

/**
 * Response builders for protocol endpoints. Every response carries {@code Cache-Control: no-store}
 * and {@code Pragma: no-cache} (RFC 6749 §5.1), plus any extra headers (DPoP-Nonce, ...).
 */
public final class Responses {

  public static final String JSON = "application/json;charset=UTF-8";
  public static final String HTML = "text/html;charset=UTF-8";
  public static final String JWT = "application/jwt";
  public static final String JAVASCRIPT = "application/javascript;charset=UTF-8";
  public static final String ENTITY_STATEMENT = "application/entity-statement+jwt";
  public static final String TOKEN_INTROSPECTION = "application/token-introspection+jwt";

  private Responses() {}

  public static Result of(int status, String body, String contentType, Map<String, String> headers) {
    Result r =
        (body == null ? Results.status(status) : Results.status(status, body).as(contentType))
            .withHeader("Cache-Control", "no-store")
            .withHeader("Pragma", "no-cache");
    if (headers != null) {
      for (Map.Entry<String, String> h : headers.entrySet()) {
        r = r.withHeader(h.getKey(), h.getValue());
      }
    }
    return r;
  }

  public static Result json(int status, String body, Map<String, String> headers) {
    return of(status, body, JSON, headers);
  }

  public static Result json(int status, String body) {
    return json(status, body, null);
  }

  public static Result ok(String json) {
    return json(200, json);
  }

  public static Result ok(String json, Map<String, String> headers) {
    return json(200, json, headers);
  }

  public static Result created(String json, Map<String, String> headers) {
    return json(201, json, headers);
  }

  public static Result noContent(Map<String, String> headers) {
    return of(204, null, null, headers);
  }

  public static Result badRequest(String json) {
    return json(400, json);
  }

  public static Result badRequest(String json, Map<String, String> headers) {
    return json(400, json, headers);
  }

  public static Result unauthorized(String json, String challenge, Map<String, String> headers) {
    Result r = json(401, json, headers);
    return challenge == null ? r : r.withHeader("WWW-Authenticate", challenge);
  }

  public static Result forbidden(String json, Map<String, String> headers) {
    return json(403, json, headers);
  }

  public static Result notFound(String json) {
    return json(404, json);
  }

  public static Result tooLarge(String json, Map<String, String> headers) {
    return json(413, json, headers);
  }

  public static Result serverError(String json) {
    return json(500, json);
  }

  public static Result serverError(String json, Map<String, String> headers) {
    return json(500, json, headers);
  }

  public static Result location(String url) {
    return of(302, null, null, Map.of("Location", url));
  }

  /**
   * HTML that auto-submits an authorization response (response_mode=form_post). Authlete's markup
   * uses an inline onload handler, so this response relaxes the site-wide CSP for itself only.
   */
  public static Result form(String html) {
    return of(200, html, HTML, null)
        .withHeader(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; form-action *");
  }

  /** Bearer token error: the challenge goes into WWW-Authenticate, with no body (RFC 6750). */
  public static Result bearerError(int status, String challenge, Map<String, String> headers) {
    return of(status, null, null, headers).withHeader("WWW-Authenticate", challenge);
  }

  public static String error(String error, String description) {
    return JsonHelpers.write(
        description == null
            ? Map.of("error", error)
            : Map.of("error", error, "error_description", description));
  }
}

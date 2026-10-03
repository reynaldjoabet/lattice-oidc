package com.lattice.oidc.obb;

import com.authlete.common.util.FapiUtils;
import com.lattice.oidc.http.Jsons;
import com.lattice.oidc.http.WebException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import play.mvc.Result;
import play.mvc.Results;

/** Response conventions of the Open Banking Brasil APIs (errors envelope, interaction id). */
public final class ObbSupport {

  public static final String X_FAPI_INTERACTION_ID = "x-fapi-interaction-id";

  private ObbSupport() {}

  public static String now() {
    return Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
  }

  /** Echoes a valid incoming interaction id or generates one; malformed ids are rejected. */
  public static String outgoingInteractionId(String code, String incoming) {
    try {
      return FapiUtils.computeOutgoingInteractionId(incoming);
    } catch (IllegalArgumentException e) {
      throw new WebException(
          error(400, null, code, "Bad Request", "The format of the incoming 'x-fapi-interaction-id' is wrong."));
    }
  }

  public static Result json(int status, String interactionId, Object body) {
    Result r = body == null ? Results.status(status) : Results.status(status, Jsons.pretty(body)).as("application/json");
    return interactionId == null ? r : r.withHeader(X_FAPI_INTERACTION_ID, interactionId);
  }

  public static Result error(int status, String interactionId, String code, String title, String detail) {
    Map<String, Object> body =
        Map.of(
            "errors", List.of(Map.of("code", code, "title", title, "detail", detail == null ? "" : detail)),
            "meta", meta());
    return json(status, interactionId, body);
  }

  public static Map<String, Object> meta() {
    return Map.of("totalRecords", 1, "totalPages", 1, "requestDateTime", now());
  }

  public static Map<String, Object> links() {
    return Map.of("self", "/");
  }

  /** The {@code consent:...} scope among the granted scopes, if any. */
  public static String consentScope(String[] scopes) {
    if (scopes == null) {
      return null;
    }
    for (String s : scopes) {
      if (s != null && s.startsWith("consent:")) {
        return s;
      }
    }
    return null;
  }

}

package com.lattice.oidc.token;

import com.authlete.common.dto.TokenCreateResponse;
import com.lattice.oidc.http.Jsons;
import com.lattice.oidc.http.Responses;
import com.lattice.oidc.http.WebException;
import java.util.LinkedHashMap;
import java.util.Map;
import play.mvc.Result;

/** Token endpoint responses for grants this server completes itself via /auth/token/create. */
final class TokenResponses {
  private TokenResponses() {}

  static Result success(
      TokenCreateResponse created, String issuedTokenType, Map<String, String> headers) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put(
        "access_token",
        created.getJwtAccessToken() != null ? created.getJwtAccessToken() : created.getAccessToken());
    if (issuedTokenType != null) {
      body.put("issued_token_type", issuedTokenType);
    }
    body.put("token_type", created.getTokenType() != null ? created.getTokenType() : "Bearer");
    body.put("expires_in", created.getExpiresIn());
    if (created.getScopes() != null && created.getScopes().length > 0) {
      body.put("scope", String.join(" ", created.getScopes()));
    }
    if (created.getRefreshToken() != null) {
      body.put("refresh_token", created.getRefreshToken());
    }
    return Responses.ok(Jsons.write(body), headers);
  }

  static WebException error(int status, String error, String description, Map<String, String> headers) {
    return new WebException(Responses.json(status, Responses.error(error, description), headers));
  }
}

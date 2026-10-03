package com.lattice.oidc.models;

import java.util.List;

/** An Open Banking Brasil data-sharing consent. */
public record Consent(
    String consentId,
    List<String> permissions,
    String status,
    String creationDateTime,
    String expirationDateTime,
    String statusUpdateDateTime,
    long clientId,
    String refreshToken) {

  public Consent withRefreshToken(String token, String now) {
    return new Consent(
        consentId, permissions, status, creationDateTime, expirationDateTime, now, clientId, token);
  }
}

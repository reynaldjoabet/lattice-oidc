package com.lattice.oidc.models;

import java.util.Optional;

/** Values of the credential offer page form and, after creation, the resulting offer. */
public record CredentialOfferForm(
    String credentialConfigurationIds,
    boolean authorizationCodeGrant,
    boolean issuerState,
    boolean preAuthorizedCodeGrant,
    String txCode,
    String txCodeInputMode,
    String txCodeDescription,
    int duration,
    String endpoint,
    Optional<String> user,
    Optional<String> error,
    Optional<Created> created) {

  /** A created offer, by value ({@code credential_offer}) and by reference ({@code credential_offer_uri}). */
  public record Created(String offerLink, String offerUri, String offerUriLink, String offerJson) {}
}

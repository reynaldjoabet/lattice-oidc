package com.lattice.oidc.models;

import java.util.Optional;

/**
 * "You already have an account": an upstream sign-in whose email matches an existing password
 * account. The user links the two (confirming with that account's password) or keeps them separate.
 */
public record AccountLinkPage(
    String linkId,
    String providerName,
    String email,
    String accountName,
    String accountLoginId,
    Optional<String> error) {

  public String accountInitial() {
    return Initials.of(accountName).substring(0, 1);
  }
}

package com.lattice.oidc.models;

import com.fasterxml.jackson.annotation.JsonAlias;
import java.util.List;

/**
 * Contents of the identity providers JSON file: a top-level {@code identityProviders} array. The
 * older top-level {@code federations} member is still accepted.
 */
public record IdentityProviderConfig(@JsonAlias("federations") List<Entry> identityProviders) {

  /**
   * One provider. {@code domains} (optional) are the email domains whose users sign in through
   * it: "jane@acme.com" goes straight to the provider listing "acme.com" (home realm discovery).
   */
  public record Entry(String id, Server server, Client client, List<String> domains) {}

  public record Server(String name, String issuer) {}

  public record Client(
      String clientId, String clientSecret, String redirectUri, String idTokenSignedResponseAlg) {}
}

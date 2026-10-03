package com.lattice.oidc.models;

import java.util.List;

/**
 * Contents of the identity providers JSON file. The format is that of java-oauth-server's
 * {@code federations.json}, hence the top-level {@code federations} member.
 */
public record IdentityProviderConfig(List<Entry> federations) {

  public record Entry(String id, Server server, Client client) {}

  public record Server(String name, String issuer) {}

  public record Client(
      String clientId, String clientSecret, String redirectUri, String idTokenSignedResponseAlg) {}
}

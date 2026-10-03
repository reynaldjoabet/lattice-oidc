package com.lattice.oidc.models;

import com.fasterxml.jackson.annotation.JsonAlias;
import java.util.List;

/**
 * Contents of the identity providers JSON file: a top-level {@code identityProviders} array. The
 * entries use the format of java-oauth-server's {@code federations.json}, whose top-level
 * {@code federations} member is still accepted.
 */
public record IdentityProviderConfig(@JsonAlias("federations") List<Entry> identityProviders) {

  public record Entry(String id, Server server, Client client) {}

  public record Server(String name, String issuer) {}

  public record Client(
      String clientId, String clientSecret, String redirectUri, String idTokenSignedResponseAlg) {}
}

package com.lattice.oidc.federation;

import java.util.List;

/** Contents of the federations JSON file (same format as java-oauth-server's federations.json). */
public record FederationConfig(List<Entry> federations) {

  public record Entry(String id, Server server, Client client) {}

  public record Server(String name, String issuer) {}

  public record Client(
      String clientId, String clientSecret, String redirectUri, String idTokenSignedResponseAlg) {}
}

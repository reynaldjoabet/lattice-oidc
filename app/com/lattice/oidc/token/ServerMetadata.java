package com.lattice.oidc.token;

import com.authlete.common.api.AuthleteApi;
import com.lattice.oidc.http.Jsons;
import com.nimbusds.jose.jwk.JWKSet;
import java.text.ParseException;
import java.time.Duration;
import java.util.Map;
import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

/** This server's issuer identifier and signing keys, as configured in Authlete (cached). */
@Singleton
public final class ServerMetadata {

  private static final Duration TTL = Duration.ofMinutes(10);

  private record Snapshot(Map<String, Object> configuration, JWKSet jwks, long expiresAt) {}

  private final Provider<AuthleteApi> api;
  private volatile Snapshot snapshot;

  @Inject
  public ServerMetadata(Provider<AuthleteApi> api) {
    this.api = api;
  }

  private Snapshot snapshot() {
    Snapshot s = snapshot;
    if (s == null || System.currentTimeMillis() >= s.expiresAt()) {
      synchronized (this) {
        s = snapshot;
        if (s == null || System.currentTimeMillis() >= s.expiresAt()) {
          Map<String, Object> conf = Jsons.readMap(api.get().getServiceConfiguration(false));
          JWKSet jwks;
          try {
            String json = api.get().getServiceJwks(false, false);
            jwks = json == null || json.isEmpty() ? new JWKSet() : JWKSet.parse(json);
          } catch (ParseException e) {
            throw new IllegalStateException("Authlete returned an invalid JWK Set", e);
          }
          s = new Snapshot(conf, jwks, System.currentTimeMillis() + TTL.toMillis());
          snapshot = s;
        }
      }
    }
    return s;
  }

  public String issuer() {
    return String.valueOf(snapshot().configuration().get("issuer"));
  }

  public JWKSet jwks() {
    return snapshot().jwks();
  }

  public Object get(String metadataName) {
    return snapshot().configuration().get(metadataName);
  }
}

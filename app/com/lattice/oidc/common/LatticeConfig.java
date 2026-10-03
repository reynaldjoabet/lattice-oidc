package com.lattice.oidc.common;

import com.typesafe.config.Config;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Singleton;

/** Typed view of the {@code lattice} configuration section. */
@Singleton
public final class LatticeConfig {

  public enum CibaMode {
    SYNC,
    ASYNC,
    POLL
  }

  public record TrustedIssuer(String issuer, String jwksUri) {}

  /**
   * A resource server allowed to introspect tokens. The optional algorithms/keys enable JWT
   * introspection responses (RFC 9701) when the resource server asks for them.
   */
  public record ResourceServer(
      String id,
      String secret,
      Optional<String> uri,
      Optional<String> introspectionSignAlg,
      Optional<String> introspectionEncryptionAlg,
      Optional<String> introspectionEncryptionEnc,
      Optional<String> sharedKeyForSign,
      Optional<String> sharedKeyForEncryption,
      Optional<String> publicKeyForEncryption) {}

  public record Ciba(
      CibaMode mode,
      String baseUrl,
      Optional<String> workspace,
      double authTimeoutRatio,
      Duration requestTimeout,
      Duration pollInterval,
      int pollMaxCount,
      Duration notificationTimeout) {}

  private final Optional<String> publicBaseUrl;
  private final boolean trustProxyCertificateHeaders;
  private final boolean demoUsers;
  private final boolean testEndpointsEnabled;
  private final Optional<String> appleAppSiteAssociation;
  private final Duration interactionTtl;
  private final Duration sessionMaxLifespan;
  private final int loginMaxFailures;
  private final Duration loginLockout;
  private final List<String> satisfiedAcrs;
  private final List<TrustedIssuer> trustedIssuers;
  private final List<ResourceServer> resourceServers;
  private final Ciba ciba;
  private final Optional<String> identityProvidersFile;
  private final String credentialOfferEndpoint;
  private final boolean obbEnabled;
  private final List<String> obbRootCertificates;
  private final Optional<String> obbDirectoryJwksUri;
  private final Duration backchannelLogoutTimeout;
  private final String pairwiseSecret;

  @Inject
  public LatticeConfig(Config root) {
    Config lattice = root.getConfig("lattice");
    publicBaseUrl = optionalString(lattice, "public-base-url").map(LatticeConfig::stripSlash);
    trustProxyCertificateHeaders = lattice.getBoolean("mtls.trust-proxy-headers");
    demoUsers = lattice.getBoolean("demo-users");
    testEndpointsEnabled = lattice.getBoolean("test-endpoints.enabled");
    appleAppSiteAssociation = optionalString(lattice, "apple-app-site-association");
    interactionTtl = lattice.getDuration("session.interaction-ttl");
    sessionMaxLifespan = lattice.getDuration("session.max-lifespan");
    loginMaxFailures = lattice.getInt("login.max-failures");
    loginLockout = lattice.getDuration("login.lockout");
    satisfiedAcrs = lattice.getStringList("login.satisfied-acrs");
    trustedIssuers =
        lattice.getConfigList("trusted-jwt-issuers").stream()
            .map(t -> new TrustedIssuer(stripSlash(t.getString("issuer")), t.getString("jwks-uri")))
            .toList();
    resourceServers =
        lattice.getConfigList("resource-servers").stream()
            .map(
                server ->
                    new ResourceServer(
                        server.getString("id"),
                        server.getString("secret"),
                        optionalString(server, "uri"),
                        optionalString(server, "introspection-sign-alg"),
                        optionalString(server, "introspection-encryption-alg"),
                        optionalString(server, "introspection-encryption-enc"),
                        optionalString(server, "shared-key-for-sign"),
                        optionalString(server, "shared-key-for-encryption"),
                        optionalString(server, "public-key-for-encryption")))
            .toList();
    Config device = lattice.getConfig("ciba");
    ciba =
        new Ciba(
            CibaMode.valueOf(device.getString("mode").trim().toUpperCase()),
            stripSlash(device.getString("base-url")),
            optionalString(device, "workspace"),
            device.getDouble("auth-timeout-ratio"),
            device.getDuration("request-timeout"),
            device.getDuration("poll-interval"),
            device.getInt("poll-max-count"),
            device.getDuration("notification-timeout"));
    identityProvidersFile = optionalString(lattice, "identity-providers.file");
    credentialOfferEndpoint = lattice.getString("vci.credential-offer-endpoint");
    obbEnabled = lattice.getBoolean("obb.enabled");
    obbRootCertificates = lattice.getStringList("obb.root-certificates");
    obbDirectoryJwksUri = optionalString(lattice, "obb.directory-jwks-uri");
    backchannelLogoutTimeout = lattice.getDuration("logout.backchannel-timeout");
    pairwiseSecret =
        optionalString(lattice, "pairwise-secret")
            .orElseGet(
                () -> root.hasPath("play.http.secret.key") ? root.getString("play.http.secret.key") : "");
  }

  private static Optional<String> optionalString(Config config, String path) {
    if (!config.hasPath(path)) {
      return Optional.empty();
    }
    String value = config.getString(path).trim();
    return value.isEmpty() ? Optional.empty() : Optional.of(value);
  }

  private static String stripSlash(String url) {
    return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
  }

  public Optional<String> publicBaseUrl() {
    return publicBaseUrl;
  }

  public boolean trustProxyCertificateHeaders() {
    return trustProxyCertificateHeaders;
  }

  public boolean demoUsers() {
    return demoUsers;
  }

  public boolean testEndpointsEnabled() {
    return testEndpointsEnabled;
  }

  public Optional<String> appleAppSiteAssociation() {
    return appleAppSiteAssociation;
  }

  public Duration interactionTtl() {
    return interactionTtl;
  }

  public Duration sessionMaxLifespan() {
    return sessionMaxLifespan;
  }

  public int loginMaxFailures() {
    return loginMaxFailures;
  }

  public Duration loginLockout() {
    return loginLockout;
  }

  public List<String> satisfiedAcrs() {
    return satisfiedAcrs;
  }

  public List<TrustedIssuer> trustedIssuers() {
    return trustedIssuers;
  }

  public List<ResourceServer> resourceServers() {
    return resourceServers;
  }

  public Ciba ciba() {
    return ciba;
  }

  public Optional<String> identityProvidersFile() {
    return identityProvidersFile;
  }

  public String credentialOfferEndpoint() {
    return credentialOfferEndpoint;
  }

  public boolean obbEnabled() {
    return obbEnabled;
  }

  public List<String> obbRootCertificates() {
    return obbRootCertificates;
  }

  public Optional<String> obbDirectoryJwksUri() {
    return obbDirectoryJwksUri;
  }

  public String pairwiseSecret() {
    return pairwiseSecret;
  }

  public Duration backchannelLogoutTimeout() {
    return backchannelLogoutTimeout;
  }
}

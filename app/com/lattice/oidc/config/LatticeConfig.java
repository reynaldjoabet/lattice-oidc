package com.lattice.oidc.config;

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
  private final Optional<String> federationsFile;
  private final String credentialOfferEndpoint;
  private final boolean obbEnabled;
  private final List<String> obbRootCertificates;
  private final Optional<String> obbDirectoryJwksUri;
  private final Duration backchannelLogoutTimeout;
  private final String pairwiseSecret;

  @Inject
  public LatticeConfig(Config root) {
    Config c = root.getConfig("lattice");
    publicBaseUrl = opt(c, "public-base-url").map(LatticeConfig::stripSlash);
    trustProxyCertificateHeaders = c.getBoolean("mtls.trust-proxy-headers");
    demoUsers = c.getBoolean("demo-users");
    testEndpointsEnabled = c.getBoolean("test-endpoints.enabled");
    appleAppSiteAssociation = opt(c, "apple-app-site-association");
    interactionTtl = c.getDuration("session.interaction-ttl");
    sessionMaxLifespan = c.getDuration("session.max-lifespan");
    loginMaxFailures = c.getInt("login.max-failures");
    loginLockout = c.getDuration("login.lockout");
    satisfiedAcrs = c.getStringList("login.satisfied-acrs");
    trustedIssuers =
        c.getConfigList("trusted-jwt-issuers").stream()
            .map(t -> new TrustedIssuer(stripSlash(t.getString("issuer")), t.getString("jwks-uri")))
            .toList();
    resourceServers =
        c.getConfigList("resource-servers").stream()
            .map(
                s ->
                    new ResourceServer(
                        s.getString("id"),
                        s.getString("secret"),
                        opt(s, "uri"),
                        opt(s, "introspection-sign-alg"),
                        opt(s, "introspection-encryption-alg"),
                        opt(s, "introspection-encryption-enc"),
                        opt(s, "shared-key-for-sign"),
                        opt(s, "shared-key-for-encryption"),
                        opt(s, "public-key-for-encryption")))
            .toList();
    Config ad = c.getConfig("ciba");
    ciba =
        new Ciba(
            CibaMode.valueOf(ad.getString("mode").trim().toUpperCase()),
            stripSlash(ad.getString("base-url")),
            opt(ad, "workspace"),
            ad.getDouble("auth-timeout-ratio"),
            ad.getDuration("request-timeout"),
            ad.getDuration("poll-interval"),
            ad.getInt("poll-max-count"),
            ad.getDuration("notification-timeout"));
    federationsFile = opt(c, "federation.file");
    credentialOfferEndpoint = c.getString("vci.credential-offer-endpoint");
    obbEnabled = c.getBoolean("obb.enabled");
    obbRootCertificates = c.getStringList("obb.root-certificates");
    obbDirectoryJwksUri = opt(c, "obb.directory-jwks-uri");
    backchannelLogoutTimeout = c.getDuration("logout.backchannel-timeout");
    pairwiseSecret =
        opt(c, "pairwise-secret")
            .orElseGet(
                () -> root.hasPath("play.http.secret.key") ? root.getString("play.http.secret.key") : "");
  }

  private static Optional<String> opt(Config c, String path) {
    if (!c.hasPath(path)) {
      return Optional.empty();
    }
    String v = c.getString(path).trim();
    return v.isEmpty() ? Optional.empty() : Optional.of(v);
  }

  private static String stripSlash(String s) {
    return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
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

  public Optional<String> federationsFile() {
    return federationsFile;
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

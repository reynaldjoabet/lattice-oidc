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
    /** Signed-in end-users approve requests on Lattice's own page. */
    BUILTIN,
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
  private final List<String> adminLoginIds;
  private final Passkeys passkeys;
  private final Mail mail;
  private final Recovery recovery;

  /** WebAuthn relying party settings. */
  public record Passkeys(String rpId, List<String> origins, Duration offerInterval, String acr) {}

  /** Outgoing email; without an SMTP host, messages are logged instead. */
  public record Mail(
      String from, Optional<String> smtpHost, int smtpPort, Optional<String> smtpUsername,
      Optional<String> smtpPassword, boolean startTls) {}

  /** Password reset links: lifetime and per-account rate limit. */
  public record Recovery(Duration linkLifetime, int maxRequests, Duration window) {}

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
    adminLoginIds = stringList(lattice, "admin.login-ids");
    passkeys =
        new Passkeys(
            lattice.getString("passkeys.rp-id"),
            stringList(lattice, "passkeys.origins"),
            lattice.getDuration("passkeys.offer-interval"),
            lattice.getString("passkeys.acr"));
    mail =
        new Mail(
            lattice.getString("mail.from"),
            optionalString(lattice, "mail.smtp.host"),
            lattice.getInt("mail.smtp.port"),
            optionalString(lattice, "mail.smtp.username"),
            optionalString(lattice, "mail.smtp.password"),
            lattice.getBoolean("mail.smtp.starttls"));
    recovery =
        new Recovery(
            lattice.getDuration("recovery.link-lifetime"),
            lattice.getInt("recovery.max-requests"),
            lattice.getDuration("recovery.window"));
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

  /** A list setting that may also be given as one comma-separated string (environment variables). */
  private static List<String> stringList(Config config, String path) {
    if (!config.hasPath(path)) {
      return List.of();
    }
    List<String> values =
        config.getValue(path).valueType() == com.typesafe.config.ConfigValueType.LIST
            ? config.getStringList(path)
            : List.of(config.getString(path).split(","));
    return values.stream().map(String::trim).filter(value -> !value.isEmpty()).toList();
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

  public Passkeys passkeys() {
    return passkeys;
  }

  public Mail mail() {
    return mail;
  }

  public Recovery recovery() {
    return recovery;
  }

  /** Login IDs allowed to open the operator console (empty: nobody). */
  public List<String> adminLoginIds() {
    return adminLoginIds;
  }
}

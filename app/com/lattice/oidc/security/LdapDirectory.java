package com.lattice.oidc.security;

import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.UserStore;
import com.typesafe.config.Config;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.StartTLSPostConnectProcessor;
import com.unboundid.util.ssl.HostNameSSLSocketVerifier;
import com.unboundid.util.ssl.JVMDefaultTrustManager;
import com.unboundid.util.ssl.PEMFileTrustManager;
import com.unboundid.util.ssl.TrustStoreTrustManager;
import com.unboundid.util.ssl.SSLUtil;
import java.io.File;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import javax.inject.Inject;
import javax.inject.Singleton;
import javax.net.SocketFactory;
import javax.net.ssl.X509TrustManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.inject.ApplicationLifecycle;

/**
 * Users from an LDAP directory or Active Directory ({@code lattice.ldap}), the way Keycloak's user
 * federation works in read-only mode:
 *
 * <ul>
 *   <li>A sign-in whose login ID or email isn't a local account is looked up in the directory with
 *       {@code user-filter}, and the password is checked with an LDAP bind as that entry.
 *   <li>On success the user is copied into Lattice's own store, keyed by the entry's stable id
 *       ({@code entryUUID}, or {@code objectGUID} on Active Directory), and the copy is refreshed at
 *       every sign-in. Passkeys, authenticator apps and sessions stay in Lattice.
 *   <li>The directory is never written to: such accounts have no Lattice password, so password
 *       change and reset are left to the directory.
 * </ul>
 *
 * Searches use a pooled connection bound as {@code bind-dn}. Use {@code ldaps://} or {@code
 * start-tls}, so passwords aren't sent in clear. The directory's certificate must chain to a CA the
 * JVM trusts or one in {@code trust-store}, and name the host in {@code url}.
 */
@Singleton
public final class LdapDirectory {

  private static final Logger LOG = LoggerFactory.getLogger(LdapDirectory.class);

  /** The attribute marking a user that came from the directory, holding its entry DN. */
  public static final String DN_ATTRIBUTE = "ldapDn";

  /** Thrown when the directory can't be reached or answers with an error (not a wrong password). */
  public static final class Unavailable extends Exception {
    Unavailable(String message, Throwable cause) {
      super(message, cause);
    }
  }

  /**
   * For the operator console, on this server: whether the directory answers now, the connection pool,
   * sign-ins checked against it since startup, and the last error (search or bind) with its time.
   */
  public record Status(
      String url,
      boolean reachable,
      String detail,
      int openConnections,
      int maximumConnections,
      long signIns,
      Optional<Instant> lastErrorAt,
      Optional<String> lastError) {}

  private record Failure(Instant at, String message) {}

  private final boolean enabled;
  private final String url;
  private final AtomicLong signIns = new AtomicLong();
  private final AtomicReference<Failure> lastFailure = new AtomicReference<>();
  private final UserStore users;
  private final LDAPConnectionPool pool;
  private final String baseDn;
  private final String userFilter;
  private final Map<String, String> attributes;
  private final boolean trustEmail;

  @Inject
  public LdapDirectory(Config config, UserStore users, ApplicationLifecycle lifecycle) {
    Config ldap = config.getConfig("lattice.ldap");
    this.enabled = ldap.getBoolean("enabled");
    this.url = ldap.getString("url");
    this.users = users;
    this.baseDn = ldap.getString("base-dn");
    this.userFilter = ldap.getString("user-filter");
    this.trustEmail = ldap.getBoolean("trust-email");
    Config mapped = ldap.getConfig("attributes");
    this.attributes = new HashMap<>();
    for (String claim : List.of("id", "login-id", "email", "name", "given-name", "family-name", "phone-number")) {
      attributes.put(claim, mapped.getString(claim));
    }
    this.pool = enabled ? connect(ldap) : null;
    if (pool != null) {
      lifecycle.addStopHook(
          () -> {
            pool.close();
            return CompletableFuture.completedFuture(null);
          });
    }
  }

  private static LDAPConnectionPool connect(Config ldap) {
    try {
      LDAPURL url = new LDAPURL(ldap.getString("url"));
      boolean ldaps = "ldaps".equalsIgnoreCase(url.getScheme());
      boolean startTlsEnabled = !ldaps && ldap.getBoolean("start-tls");
      if (!ldaps && !startTlsEnabled) {
        LOG.warn("The LDAP directory {} is used without TLS: passwords are sent in clear. Use ldaps:// or start-tls.", url);
      }
      SSLUtil ssl = new SSLUtil(trustManager(ldap));
      SocketFactory sockets = ldaps ? ssl.createSSLSocketFactory() : SocketFactory.getDefault();
      LDAPConnectionOptions options = new LDAPConnectionOptions();
      options.setConnectTimeoutMillis((int) ldap.getDuration("connect-timeout").toMillis());
      options.setResponseTimeoutMillis(ldap.getDuration("response-timeout").toMillis());
      // A trusted certificate must also be for this host (wildcards allowed).
      options.setSSLSocketVerifier(new HostNameSSLSocketVerifier(true));
      LDAPConnection connection = new LDAPConnection(sockets, options, url.getHost(), url.getPort());
      StartTLSPostConnectProcessor startTls = null;
      if (startTlsEnabled) {
        startTls = new StartTLSPostConnectProcessor(ssl.createSSLSocketFactory());
        startTls.processPreAuthenticatedConnection(connection);
      }
      String bindDn = ldap.getString("bind-dn");
      if (!bindDn.isBlank()) {
        connection.bind(bindDn, ldap.getString("bind-password"));
      }
      LDAPConnectionPool pool = new LDAPConnectionPool(connection, 1, ldap.getInt("maximum-connections"), startTls);
      LOG.info("LDAP directory ready: {}", url);
      return pool;
    } catch (LDAPException | GeneralSecurityException e) {
      // Fails the deployment: a configured directory that can't be reached is a setup error.
      throw new IllegalStateException("Could not connect to the LDAP directory: " + e.getMessage(), e);
    }
  }

  /** The JVM's trusted CAs, or those in {@code trust-store} (a PEM file, or a PKCS#12 or JKS store). */
  private static X509TrustManager trustManager(Config ldap) throws GeneralSecurityException {
    String path = ldap.getString("trust-store").trim();
    if (path.isEmpty()) {
      return JVMDefaultTrustManager.getInstance();
    }
    File file = new File(path);
    if (!file.isFile()) {
      throw new GeneralSecurityException("lattice.ldap.trust-store " + path + " is not a file");
    }
    String name = path.toLowerCase(Locale.ROOT);
    if (name.endsWith(".pem") || name.endsWith(".crt") || name.endsWith(".cer")) {
      return new PEMFileTrustManager(file);
    }
    String password = ldap.getString("trust-store-password");
    String format = name.endsWith(".jks") ? "JKS" : "PKCS12";
    TrustStoreTrustManager manager =
        new TrustStoreTrustManager(file, password.isEmpty() ? null : password.toCharArray(), format, true);
    // Read it now, so a wrong password or format fails at startup instead of at the first sign-in.
    if (manager.getAcceptedIssuers().length == 0) {
      throw new GeneralSecurityException("lattice.ldap.trust-store " + path + " has no certificates");
    }
    return manager;
  }

  public boolean enabled() {
    return enabled;
  }

  /** Whether the user came from the directory (so their password is checked there). */
  public static boolean isFederated(User user) {
    return user.getAttribute(DN_ATTRIBUTE) != null;
  }

  /**
   * Checks the password against the directory entry for {@code identifier} (login ID or email).
   * On success the user is copied into, or refreshed in, Lattice's store and returned.
   */
  public Optional<User> authenticate(String identifier, String password) throws Unavailable {
    if (!enabled || identifier == null || identifier.isBlank() || password == null || password.isEmpty()) {
      // An empty password would be an anonymous bind, which directories accept.
      return Optional.empty();
    }
    SearchResultEntry entry;
    try {
      Filter filter = Filter.create(userFilter.replace("{0}", Filter.encodeValue(identifier.trim())));
      entry = pool.searchForEntry(baseDn, SearchScope.SUB, filter, attributes.values().toArray(String[]::new));
    } catch (LDAPException e) {
      throw unavailable("LDAP search failed: " + e.getMessage(), e);
    }
    if (entry == null) {
      return Optional.empty();
    }
    try {
      pool.bindAndRevertAuthentication(entry.getDN(), password);
    } catch (LDAPException e) {
      if (e.getResultCode() == ResultCode.INVALID_CREDENTIALS) {
        return Optional.empty();
      }
      throw unavailable("LDAP bind failed: " + e.getMessage(), e);
    }
    signIns.incrementAndGet();
    User user = imported(entry);
    users.save(user);
    return Optional.of(user);
  }

  private Unavailable unavailable(String message, LDAPException cause) {
    lastFailure.set(new Failure(Instant.now(), message));
    return new Unavailable(message, cause);
  }

  /** The directory's status, reading its root DSE now (empty when no directory is configured). */
  public Optional<Status> status() {
    if (!enabled) {
      return Optional.empty();
    }
    boolean reachable;
    String detail;
    try {
      RootDSE root = pool.getRootDSE();
      reachable = true;
      String vendor = root == null ? null : root.getVendorName();
      detail = vendor == null ? "Answering" : "Answering (" + vendor + ")";
    } catch (LDAPException e) {
      reachable = false;
      detail = e.getResultCode() + ": " + e.getDiagnosticMessage();
    }
    Failure failure = lastFailure.get();
    return Optional.of(
        new Status(
            url,
            reachable,
            detail,
            pool.getCurrentAvailableConnections(),
            pool.getMaximumAvailableConnections(),
            signIns.get(),
            Optional.ofNullable(failure).map(Failure::at),
            Optional.ofNullable(failure).map(Failure::message)));
  }

  /** The directory entry as a Lattice user (no password: it's checked in the directory). */
  private User imported(SearchResultEntry entry) {
    String subject = id(entry);
    Map<String, Object> claims = new HashMap<>();
    put(claims, "email", entry, "email");
    put(claims, "name", entry, "name");
    put(claims, "given_name", entry, "given-name");
    put(claims, "family_name", entry, "family-name");
    put(claims, "phone_number", entry, "phone-number");
    if (claims.containsKey("email")) {
      claims.put("email_verified", trustEmail);
    }
    Map<String, Object> userAttributes = new HashMap<>();
    // Keep attributes Lattice added itself (accepted terms, required actions, ...).
    users.bySubject(subject).ifPresent(existing -> userAttributes.putAll(existing.attributes()));
    userAttributes.put(DN_ATTRIBUTE, entry.getDN());
    String loginId = entry.getAttributeValue(attributes.get("login-id"));
    return new User(subject, loginId, null, claims, userAttributes, List.of());
  }

  private void put(Map<String, Object> claims, String claim, SearchResultEntry entry, String mapping) {
    String attribute = attributes.get(mapping);
    if (!attribute.isBlank() && entry.hasAttribute(attribute)) {
      claims.put(claim, entry.getAttributeValue(attribute));
    }
  }

  /** The entry's stable id: Active Directory's binary objectGUID as a UUID, otherwise the text value. */
  private String id(SearchResultEntry entry) {
    String attribute = attributes.get("id");
    Attribute value = entry.getAttribute(attribute);
    if (value == null) {
      throw new IllegalStateException("The directory entry " + entry.getDN() + " has no " + attribute);
    }
    if ("objectGUID".equalsIgnoreCase(attribute)) {
      byte[] guid = value.getValueByteArray();
      // objectGUID stores its first three fields little-endian.
      ByteBuffer bytes = ByteBuffer.allocate(16);
      bytes.put(new byte[] {guid[3], guid[2], guid[1], guid[0], guid[5], guid[4], guid[7], guid[6]});
      bytes.put(guid, 8, 8);
      bytes.flip();
      return new UUID(bytes.getLong(), bytes.getLong()).toString();
    }
    return value.getValue();
  }
}

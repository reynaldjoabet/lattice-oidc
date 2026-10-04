package com.lattice.oidc.models;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * An end-user account.
 *
 * <p>Claims are stored by their OIDC name; localized variants use the {@code name#tag} key (for
 * example {@code name#ja}). Attributes hold non-claim data such as the CIBA user code ({@code
 * code}) or mdoc namespaces keyed by doctype.
 */
public final class User implements com.authlete.common.types.User {

  private final String subject;
  private final String loginId;
  private final String passwordHash;
  private final Map<String, Object> claims;
  private final Map<String, Object> attributes;
  private final List<Map<String, Object>> verifiedClaims;

  public User(
      String subject,
      String loginId,
      String passwordHash,
      Map<String, Object> claims,
      Map<String, Object> attributes,
      List<Map<String, Object>> verifiedClaims) {
    this.subject = subject;
    this.loginId = loginId;
    this.passwordHash = passwordHash;
    this.claims = claims == null ? Map.of() : Collections.unmodifiableMap(claims);
    this.attributes = attributes == null ? Map.of() : Collections.unmodifiableMap(attributes);
    this.verifiedClaims = verifiedClaims == null ? List.of() : List.copyOf(verifiedClaims);
  }

  @Override
  public String getSubject() {
    return subject;
  }

  public String loginId() {
    return loginId;
  }

  /** Argon2 hash, or null for accounts that cannot log in with a password (federated). */
  public String passwordHash() {
    return passwordHash;
  }

  @Override
  public Object getClaim(String claimName, String languageTag) {
    if (claimName == null) {
      return null;
    }
    if (languageTag != null && !languageTag.isEmpty()) {
      return claims.get(claimName + "#" + languageTag);
    }
    return claims.get(claimName);
  }

  @Override
  public Object getAttribute(String attributeName) {
    return attributeName == null ? null : attributes.get(attributeName);
  }

  public Map<String, Object> claims() {
    return claims;
  }

  /** eKYC/IDA verified-claims datasets (each a {@code verified_claims} object). */
  public List<Map<String, Object>> verifiedClaims() {
    return verifiedClaims;
  }

  /** The same account with a new password hash. */
  public User withPasswordHash(String newPasswordHash) {
    return new User(subject, loginId, newPasswordHash, claims, attributes, verifiedClaims);
  }

  /** The email claim, if the account has one. */
  public java.util.Optional<String> email() {
    return claims.get("email") instanceof String value ? java.util.Optional.of(value) : java.util.Optional.empty();
  }

  /** Display name for UI purposes. */
  public String displayName() {
    Object name = claims.get("name");
    return name instanceof String s ? s : (loginId != null ? loginId : subject);
  }
}

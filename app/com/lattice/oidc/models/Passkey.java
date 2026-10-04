package com.lattice.oidc.models;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * A registered WebAuthn credential (passkey or security key). Byte values are base64url.
 *
 * @param id credential ID
 * @param subject the account it signs in to
 * @param userHandle the WebAuthn user handle of that account
 * @param publicKeyCose the credential public key (COSE)
 * @param signatureCount the authenticator's last signature counter (0 for most passkeys)
 * @param backedUp whether it is synced (iCloud Keychain, Google Password Manager, ...)
 */
public record Passkey(
    String id,
    String subject,
    String userHandle,
    String publicKeyCose,
    long signatureCount,
    String name,
    Instant createdAt,
    Optional<Instant> lastUsedAt,
    boolean backedUp,
    Set<String> transports) {

  private static final DateTimeFormatter DATE =
      DateTimeFormatter.ofPattern("d MMM yyyy", Locale.ENGLISH).withZone(ZoneOffset.UTC);

  public Passkey withName(String newName) {
    return new Passkey(id, subject, userHandle, publicKeyCose, signatureCount, newName, createdAt, lastUsedAt, backedUp, transports);
  }

  public Passkey used(long newSignatureCount, Instant at) {
    return new Passkey(id, subject, userHandle, publicKeyCose, newSignatureCount, name, createdAt, Optional.of(at), backedUp, transports);
  }

  /** "Synced passkey" or "This device only" / "Security key". */
  public String kind() {
    if (backedUp) {
      return "Synced passkey";
    }
    return transports.contains("usb") || transports.contains("nfc") ? "Security key" : "This device only";
  }

  public String created() {
    return DATE.format(createdAt);
  }

  /** "used today", "used 3 days ago", "not used yet". */
  public String lastUsed() {
    if (lastUsedAt.isEmpty()) {
      return "not used yet";
    }
    long days = java.time.Duration.between(lastUsedAt.get(), Instant.now()).toDays();
    return days <= 0 ? "used today" : days == 1 ? "used yesterday" : "used " + days + " days ago";
  }
}

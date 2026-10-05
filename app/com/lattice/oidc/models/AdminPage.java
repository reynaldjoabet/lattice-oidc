package com.lattice.oidc.models;

import com.lattice.oidc.security.LdapDirectory;
import com.lattice.oidc.security.SecondFactors;
import com.lattice.oidc.security.Webhooks;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/** The operator console overview. All values are for this node. */
public record AdminPage(
    String adminName,
    Optional<String> issuer,
    boolean authleteUp,
    Optional<String> authleteReason,
    long activeSessions,
    List<String> identityProviders,
    long accountsWithFailedLogins,
    String storage,
    List<StorageRow> storageRows,
    SecondFactors.Status twoStep,
    Optional<LdapDirectory.Status> directory,
    List<Webhooks.EndpointStatus> webhooks,
    List<Event> events) {

  private static final DateTimeFormatter TIME =
      DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.ENGLISH).withZone(ZoneOffset.UTC);

  /** An instant as shown in the console (UTC), or a dash. */
  public static String time(Optional<Instant> instant) {
    return instant.map(TIME::format).orElse("—");
  }

  /** Stored entries of one kind (for example pending sign-ins), across every server. */
  public record StorageRow(String name, long entries) {}

  /**
   * A recent audit event; {@code tone} is good, bad or neutral (for the label colour), and {@code
   * details} the event's other fields ("method: password + totp").
   */
  public record Event(String time, String name, String subject, String client, String ip, String details, String tone) {}
}

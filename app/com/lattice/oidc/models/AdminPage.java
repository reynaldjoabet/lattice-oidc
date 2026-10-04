package com.lattice.oidc.models;

import java.util.List;
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
    List<Event> events) {

  /** Stored entries of one kind (for example pending sign-ins), across every server. */
  public record StorageRow(String name, long entries) {}

  /** A recent audit event; {@code tone} is good, bad or neutral (for the label colour). */
  public record Event(String time, String name, String subject, String client, String ip, String tone) {}
}

package com.lattice.oidc.models;

import com.lattice.oidc.common.CacheStatistics;
import java.util.List;
import java.util.Optional;

/** The operator console overview. All values are for this node. */
public record AdminPage(
    String adminName,
    Optional<String> issuer,
    boolean authleteUp,
    Optional<String> authleteReason,
    long activeSessions,
    Optional<Long> sessionsMaximum,
    List<String> identityProviders,
    long accountsWithFailedLogins,
    List<CacheStatistics.Row> caches,
    List<Event> events) {

  /** A recent audit event; {@code tone} is good, bad or neutral (for the label colour). */
  public record Event(String time, String name, String subject, String client, String ip, String tone) {}
}

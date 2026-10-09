package com.lattice.oidc.stores;

import com.google.inject.ImplementedBy;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Short-lived state shared by every server: pending sign-ins, reset links, CIBA requests, native
 * SSO device secrets and sign-in alerts. Entries live in a {@code namespace}, expire on their own,
 * and carry their value as JSON (see {@code JsonHelpers}). An entry may be bound to a browser ({@code
 * owner}) and indexed by account ({@code subject}).
 *
 * <p>Implementations: {@link InMemoryEphemeralStore} (one server, development and tests) and the
 * PostgreSQL store ({@code lattice.storage = postgres}).
 */
@ImplementedBy(InMemoryEphemeralStore.class)
public interface EphemeralStore {

  /** A stored entry. {@code owner} and {@code subject} may be null. */
  record Entry(String namespace, String key, String owner, String subject, String json, Instant expiresAt) {}

  /** Creates or replaces an entry. */
  void put(String namespace, String key, String owner, String subject, String json, Duration ttl);

  /** The entry, unless it has expired. */
  Optional<Entry> get(String namespace, String key);

  /** Removes and returns the entry in one step: of two concurrent callers, only one gets it. */
  Optional<Entry> take(String namespace, String key);

  /** The account's unexpired entries in a namespace, oldest first. */
  List<Entry> bySubject(String namespace, String subject);

  void delete(String namespace, String key);

  /** Deletes the account's entries in a namespace; returns how many there were. */
  int deleteBySubject(String namespace, String subject);

  /** Unexpired entries in a namespace (for the operator console). */
  long count(String namespace);

  /** Unexpired entries per namespace (for the operator console). */
  java.util.Map<String, Long> counts();
}

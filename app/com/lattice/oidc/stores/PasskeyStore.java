package com.lattice.oidc.stores;

import com.google.inject.ImplementedBy;
import com.lattice.oidc.models.Passkey;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/** Registered passkeys. The default implementation is in-memory; swap in a database-backed one. */
@ImplementedBy(InMemoryPasskeyStore.class)
public interface PasskeyStore {

  List<Passkey> forSubject(String subject);

  Optional<Passkey> byId(String credentialId);

  void save(Passkey passkey);

  void delete(String credentialId);

  /** The account's WebAuthn user handle (random, stable), created on first use. */
  String userHandle(String subject);

  Optional<String> subjectForUserHandle(String userHandle);

  /** When the "create a passkey" offer was last shown to the account. */
  Optional<Instant> offeredAt(String subject);

  void markOffered(String subject, Instant at);

  /** Number of accounts with at least one passkey. */
  long accountsWithPasskeys();
}

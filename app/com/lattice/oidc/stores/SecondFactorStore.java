package com.lattice.oidc.stores;

import com.google.inject.ImplementedBy;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Second factors: an authenticator-app secret (encrypted) per account, and single-use recovery
 * codes (stored as keyed hashes). Using a code is one atomic step, so a code can't be used twice,
 * even from two servers at once.
 */
@ImplementedBy(InMemorySecondFactorStore.class)
public interface SecondFactorStore {

  /** An authenticator app: its encrypted secret and the last time step a code was accepted for. */
  record Totp(String subject, String encryptedSecret, Instant createdAt, long lastUsedStep) {}

  Optional<Totp> totp(String subject);

  void saveTotp(Totp totp);

  void deleteTotp(String subject);

  /** Records that a code for {@code step} was used; false if that step or a later one already was. */
  boolean useTotpStep(String subject, long step);

  /** Replaces the account's recovery codes. */
  void replaceRecoveryCodes(String subject, List<String> codeHashes);

  /** Uses up a recovery code; false if it isn't one of the account's unused codes. */
  boolean useRecoveryCode(String subject, String codeHash);

  int remainingRecoveryCodes(String subject);

  void deleteRecoveryCodes(String subject);

  /** Accounts with an authenticator app (for the operator console). */
  long accountsWithTotp();
}

package com.lattice.oidc.stores;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.inject.Singleton;

/** {@link SecondFactorStore} in memory, for one server (development and tests). */
@Singleton
public final class InMemorySecondFactorStore implements SecondFactorStore {

  private final Map<String, Totp> totps = new ConcurrentHashMap<>();
  private final Map<String, Set<String>> recoveryCodes = new ConcurrentHashMap<>();

  @Override
  public Optional<Totp> totp(String subject) {
    return Optional.ofNullable(totps.get(subject));
  }

  @Override
  public void saveTotp(Totp totp) {
    totps.put(totp.subject(), totp);
  }

  @Override
  public void deleteTotp(String subject) {
    totps.remove(subject);
  }

  @Override
  public boolean useTotpStep(String subject, long step) {
    boolean[] accepted = {false};
    totps.computeIfPresent(
        subject,
        (key, totp) -> {
          if (step > totp.lastUsedStep()) {
            accepted[0] = true;
            return new Totp(totp.subject(), totp.encryptedSecret(), totp.createdAt(), step);
          }
          return totp;
        });
    return accepted[0];
  }

  @Override
  public void replaceRecoveryCodes(String subject, List<String> codeHashes) {
    recoveryCodes.put(subject, ConcurrentHashMap.newKeySet());
    recoveryCodes.get(subject).addAll(codeHashes);
  }

  @Override
  public boolean useRecoveryCode(String subject, String codeHash) {
    Set<String> codes = recoveryCodes.get(subject);
    return codes != null && codes.remove(codeHash);
  }

  @Override
  public int remainingRecoveryCodes(String subject) {
    Set<String> codes = recoveryCodes.get(subject);
    return codes == null ? 0 : codes.size();
  }

  @Override
  public void deleteRecoveryCodes(String subject) {
    recoveryCodes.remove(subject);
  }

  @Override
  public long accountsWithTotp() {
    return totps.size();
  }
}

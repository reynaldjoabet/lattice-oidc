package com.lattice.oidc.stores;

import java.util.Comparator;
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
  public boolean replaceTotpSecret(String subject, String expected, String replacement) {
    boolean[] replaced = {false};
    totps.computeIfPresent(
        subject,
        (key, totp) -> {
          if (totp.encryptedSecret().equals(expected)) {
            replaced[0] = true;
            return new Totp(totp.subject(), replacement, totp.createdAt(), totp.lastUsedStep());
          }
          return totp;
        });
    return replaced[0];
  }

  @Override
  public List<Totp> totps(String afterSubject, int limit) {
    return totps.values().stream()
        .filter(totp -> afterSubject == null || totp.subject().compareTo(afterSubject) > 0)
        .sorted(Comparator.comparing(Totp::subject))
        .limit(limit)
        .toList();
  }

  @Override
  public long totpsNotUnderKey(String keyId) {
    return totps.values().stream().filter(totp -> !totp.encryptedSecret().startsWith(keyId + ":")).count();
  }

  @Override
  public long accountsWithRecoveryCodesNotUnderKey(String keyId) {
    return recoveryCodes.values().stream()
        .filter(codes -> codes.stream().anyMatch(hash -> !hash.startsWith(keyId + ":")))
        .count();
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

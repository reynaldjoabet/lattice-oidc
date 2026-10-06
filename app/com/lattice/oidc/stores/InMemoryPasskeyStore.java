package com.lattice.oidc.stores;

import com.lattice.oidc.models.Passkey;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.inject.Singleton;

/** Thread-safe in-memory passkey store (lost on restart, like {@link InMemoryUserStore}). */
@Singleton
public final class InMemoryPasskeyStore implements PasskeyStore {

  private static final SecureRandom RANDOM = new SecureRandom();

  private final Map<String, Passkey> byId = new ConcurrentHashMap<>();
  private final Map<String, String> handles = new ConcurrentHashMap<>();
  private final Map<String, Instant> offers = new ConcurrentHashMap<>();

  @Override
  public List<Passkey> forSubject(String subject) {
    return byId.values().stream()
        .filter(passkey -> passkey.subject().equals(subject))
        .sorted(Comparator.comparing(Passkey::createdAt))
        .toList();
  }

  @Override
  public Optional<Passkey> byId(String credentialId) {
    return credentialId == null ? Optional.empty() : Optional.ofNullable(byId.get(credentialId));
  }

  @Override
  public void save(Passkey passkey) {
    byId.put(passkey.id(), passkey);
  }

  @Override
  public void delete(String credentialId) {
    byId.remove(credentialId);
  }

  @Override
  public String userHandle(String subject) {
    return handles.computeIfAbsent(
        subject,
        ignored -> {
          byte[] bytes = new byte[32];
          RANDOM.nextBytes(bytes);
          return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        });
  }

  @Override
  public Optional<String> subjectForUserHandle(String userHandle) {
    return handles.entrySet().stream()
        .filter(entry -> entry.getValue().equals(userHandle))
        .map(Map.Entry::getKey)
        .findFirst();
  }

  @Override
  public Optional<Instant> offeredAt(String subject) {
    return Optional.ofNullable(offers.get(subject));
  }

  @Override
  public void markOffered(String subject, Instant at) {
    offers.put(subject, at);
  }

  @Override
  public long accountsWithPasskeys() {
    return byId.values().stream().map(Passkey::subject).distinct().count();
  }
}

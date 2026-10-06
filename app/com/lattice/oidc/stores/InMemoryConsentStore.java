package com.lattice.oidc.stores;

import com.lattice.oidc.models.Consent;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.inject.Singleton;

/** {@link ConsentStore} in memory, for one server (development and tests). */
@Singleton
public final class InMemoryConsentStore implements ConsentStore {

  private record Stored(Consent consent, Instant keepUntil) {}

  private final Map<String, Stored> consents = new ConcurrentHashMap<>();

  @Override
  public Optional<Consent> find(String consentId) {
    if (consentId == null) {
      return Optional.empty();
    }
    return Optional.ofNullable(consents.get(consentId))
        .filter(stored -> stored.keepUntil().isAfter(Instant.now()))
        .map(Stored::consent);
  }

  @Override
  public void save(Consent consent) {
    consents.values().removeIf(stored -> !stored.keepUntil().isAfter(Instant.now()));
    consents.put(consent.consentId(), new Stored(consent, ConsentStore.keepUntil(consent.expirationDateTime())));
  }

  @Override
  public void delete(String consentId) {
    if (consentId != null) {
      consents.remove(consentId);
    }
  }
}

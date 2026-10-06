package com.lattice.oidc.stores;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.inject.Singleton;

/** {@link AppConsentStore} in memory, for one server (development and tests). */
@Singleton
public final class InMemoryAppConsentStore implements AppConsentStore {

  private final Map<String, AppConsent> consents = new ConcurrentHashMap<>();

  private static String key(String subject, long clientId) {
    return clientId + "|" + subject;
  }

  @Override
  public Optional<AppConsent> find(String subject, long clientId) {
    return Optional.ofNullable(consents.get(key(subject, clientId)));
  }

  @Override
  public void put(AppConsent consent) {
    consents.put(key(consent.subject(), consent.clientId()), consent);
  }

  @Override
  public void delete(String subject, long clientId) {
    consents.remove(key(subject, clientId));
  }

  @Override
  public void deleteClient(long clientId) {
    consents.values().removeIf(consent -> consent.clientId() == clientId);
  }
}

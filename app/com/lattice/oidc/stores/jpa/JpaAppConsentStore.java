package com.lattice.oidc.stores.jpa;

import com.lattice.oidc.stores.AppConsentStore;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/** {@link AppConsentStore} through JPA (entity {@link AppConsentEntity}, table {@code app_consents}). */
@Singleton
public final class JpaAppConsentStore implements AppConsentStore {

  private final JpaDatabase database;

  @Inject
  public JpaAppConsentStore(JpaDatabase database) {
    this.database = database;
  }

  @Override
  public Optional<AppConsent> find(String subject, long clientId) {
    return database.transaction(
        em ->
            Optional.ofNullable(em.find(AppConsentEntity.class, new AppConsentEntity.Key(subject, clientId)))
                .map(c -> new AppConsent(c.subject, c.clientId, words(c.scopes), words(c.claims), c.grantedAt)));
  }

  @Override
  public void put(AppConsent consent) {
    // Native SQL: an atomic upsert.
    database.transaction(
        em ->
            em.createNativeQuery(
                    """
                    INSERT INTO app_consents (subject, client_id, scopes, claims, granted_at) VALUES (?1, ?2, ?3, ?4, ?5)
                    ON CONFLICT (subject, client_id) DO UPDATE SET
                      scopes = EXCLUDED.scopes, claims = EXCLUDED.claims, granted_at = EXCLUDED.granted_at
                    """)
                .setParameter(1, consent.subject())
                .setParameter(2, consent.clientId())
                .setParameter(3, text(consent.scopes()))
                .setParameter(4, text(consent.claims()))
                .setParameter(5, consent.grantedAt())
                .executeUpdate());
  }

  @Override
  public void delete(String subject, long clientId) {
    database.transaction(
        em ->
            em.createQuery("delete from AppConsentEntity c where c.subject = :subject and c.clientId = :client")
                .setParameter("subject", subject)
                .setParameter("client", clientId)
                .executeUpdate());
  }

  @Override
  public void deleteClient(long clientId) {
    database.transaction(
        em -> em.createQuery("delete from AppConsentEntity c where c.clientId = :client").setParameter("client", clientId).executeUpdate());
  }

  /** Space-separated, as scopes are written in OAuth. */
  private static String text(Set<String> values) {
    return new TreeSet<>(values).stream().collect(Collectors.joining(" "));
  }

  private static Set<String> words(String text) {
    return text == null || text.isBlank() ? Set.of() : Set.copyOf(Arrays.asList(text.trim().split(" +")));
  }
}

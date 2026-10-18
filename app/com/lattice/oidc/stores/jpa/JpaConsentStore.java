package com.lattice.oidc.stores.jpa;

import com.lattice.oidc.common.JsonHelpers;
import com.lattice.oidc.models.Consent;
import com.lattice.oidc.stores.ConsentStore;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.time.Instant;
import java.util.Optional;

/** {@link ConsentStore} through JPA (entity {@link ObbConsentEntity}, table {@code obb_consents}). */
@Singleton
public final class JpaConsentStore implements ConsentStore {

  private final JpaDatabase database;

  @Inject
  public JpaConsentStore(JpaDatabase database) {
    this.database = database;
  }

  @Override
  public Optional<Consent> find(String consentId) {
    if (consentId == null) {
      return Optional.empty();
    }
    return database.transaction(
        em ->
            em.createQuery("select c from ObbConsentEntity c where c.consentId = :id and c.keepUntil > :now", ObbConsentEntity.class)
                .setParameter("id", consentId)
                .setParameter("now", Instant.now())
                .getResultStream()
                .findFirst()
                .map(c -> JsonHelpers.read(c.consent, Consent.class)));
  }

  @Override
  public void save(Consent consent) {
    // Native SQL: an atomic upsert.
    database.transaction(
        em ->
            em.createNativeQuery(
                    """
                    INSERT INTO obb_consents (consent_id, consent, keep_until) VALUES (?1, CAST(?2 AS jsonb), ?3)
                    ON CONFLICT (consent_id) DO UPDATE SET consent = EXCLUDED.consent, keep_until = EXCLUDED.keep_until
                    """)
                .setParameter(1, consent.consentId())
                .setParameter(2, JsonHelpers.write(consent))
                .setParameter(3, ConsentStore.keepUntil(consent.expirationDateTime()))
                .executeUpdate());
  }

  @Override
  public void delete(String consentId) {
    database.transaction(
        em -> em.createQuery("delete from ObbConsentEntity c where c.consentId = :id").setParameter("id", consentId).executeUpdate());
  }
}

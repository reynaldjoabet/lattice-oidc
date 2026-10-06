package com.lattice.oidc.stores.postgres;

import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.models.Consent;
import com.lattice.oidc.stores.ConsentStore;
import java.time.Instant;
import java.util.Optional;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/** {@link ConsentStore} in PostgreSQL (table {@code obb_consents}). */
@Singleton
public final class PostgresConsentStore implements ConsentStore {

  private final PostgresDatabase database;

  @Inject
  public PostgresConsentStore(PostgresDatabase database) {
    this.database = database;
  }

  @Override
  public Optional<Consent> find(String consentId) {
    return consentId == null
        ? Optional.empty()
        : database.queryOne(
            "SELECT consent::text FROM obb_consents WHERE consent_id = ? AND keep_until > ?",
            row -> Jsons.read(row.getString(1), Consent.class),
            consentId, Instant.now());
  }

  @Override
  public void save(Consent consent) {
    database.update(
        """
        INSERT INTO obb_consents (consent_id, consent, keep_until) VALUES (?, ?::jsonb, ?)
        ON CONFLICT (consent_id) DO UPDATE SET consent = EXCLUDED.consent, keep_until = EXCLUDED.keep_until
        """,
        consent.consentId(),
        Jsons.write(consent),
        ConsentStore.keepUntil(consent.expirationDateTime()));
  }

  @Override
  public void delete(String consentId) {
    database.update("DELETE FROM obb_consents WHERE consent_id = ?", consentId);
  }
}

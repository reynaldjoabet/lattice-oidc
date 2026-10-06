package com.lattice.oidc.stores.postgres;

import com.lattice.oidc.stores.AppConsentStore;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/** {@link AppConsentStore} in PostgreSQL (table {@code app_consents}). */
@Singleton
public final class PostgresAppConsentStore implements AppConsentStore {

  private final PostgresDatabase database;

  @Inject
  public PostgresAppConsentStore(PostgresDatabase database) {
    this.database = database;
  }

  @Override
  public Optional<AppConsent> find(String subject, long clientId) {
    return database.queryOne(
        "SELECT subject, client_id, scopes, claims, granted_at FROM app_consents WHERE subject = ? AND client_id = ?",
        row ->
            new AppConsent(
                row.getString("subject"),
                row.getLong("client_id"),
                words(row.getString("scopes")),
                words(row.getString("claims")),
                PostgresDatabase.instant(row, "granted_at")),
        subject,
        clientId);
  }

  @Override
  public void put(AppConsent consent) {
    database.update(
        """
        INSERT INTO app_consents (subject, client_id, scopes, claims, granted_at) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (subject, client_id) DO UPDATE SET
          scopes = EXCLUDED.scopes, claims = EXCLUDED.claims, granted_at = EXCLUDED.granted_at
        """,
        consent.subject(),
        consent.clientId(),
        text(consent.scopes()),
        text(consent.claims()),
        consent.grantedAt());
  }

  @Override
  public void delete(String subject, long clientId) {
    database.update("DELETE FROM app_consents WHERE subject = ? AND client_id = ?", subject, clientId);
  }

  @Override
  public void deleteClient(long clientId) {
    database.update("DELETE FROM app_consents WHERE client_id = ?", clientId);
  }

  /** Space-separated, as scopes are written in OAuth. */
  private static String text(Set<String> values) {
    return new TreeSet<>(values).stream().collect(Collectors.joining(" "));
  }

  private static Set<String> words(String text) {
    return text == null || text.isBlank() ? Set.of() : Set.copyOf(Arrays.asList(text.trim().split(" +")));
  }
}

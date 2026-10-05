package com.lattice.oidc.stores.postgres;

import com.lattice.oidc.stores.SecondFactorStore;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Singleton;

/** {@link SecondFactorStore} in PostgreSQL (tables {@code totp_credentials} and {@code recovery_codes}). */
@Singleton
public final class PostgresSecondFactorStore implements SecondFactorStore {

  private final PostgresDatabase database;

  @Inject
  public PostgresSecondFactorStore(PostgresDatabase database) {
    this.database = database;
  }

  private static Totp totp(java.sql.ResultSet row) throws java.sql.SQLException {
    return new Totp(
        row.getString("subject"), row.getString("secret"), PostgresDatabase.instant(row, "created_at"), row.getLong("last_used_step"));
  }

  @Override
  public Optional<Totp> totp(String subject) {
    return database.queryOne(
        "SELECT subject, secret, created_at, last_used_step FROM totp_credentials WHERE subject = ?",
        PostgresSecondFactorStore::totp,
        subject);
  }

  @Override
  public void saveTotp(Totp totp) {
    database.update(
        """
        INSERT INTO totp_credentials (subject, secret, created_at, last_used_step) VALUES (?, ?, ?, ?)
        ON CONFLICT (subject) DO UPDATE SET
          secret = EXCLUDED.secret, created_at = EXCLUDED.created_at, last_used_step = EXCLUDED.last_used_step
        """,
        totp.subject(), totp.encryptedSecret(), totp.createdAt(), totp.lastUsedStep());
  }

  @Override
  public void deleteTotp(String subject) {
    database.update("DELETE FROM totp_credentials WHERE subject = ?", subject);
  }

  @Override
  public boolean replaceTotpSecret(String subject, String expected, String replacement) {
    // Only the secret column: a code used meanwhile keeps its last_used_step.
    return database.update(
            "UPDATE totp_credentials SET secret = ? WHERE subject = ? AND secret = ?", replacement, subject, expected)
        == 1;
  }

  @Override
  public List<Totp> totps(String afterSubject, int limit) {
    return database.query(
        "SELECT subject, secret, created_at, last_used_step FROM totp_credentials WHERE subject > ? ORDER BY subject LIMIT ?",
        PostgresSecondFactorStore::totp,
        afterSubject == null ? "" : afterSubject,
        limit);
  }

  @Override
  public long totpsNotUnderKey(String keyId) {
    return database
        .queryOne("SELECT count(*) FROM totp_credentials WHERE secret NOT LIKE ?", row -> row.getLong(1), keyId + ":%")
        .orElse(0L);
  }

  @Override
  public long accountsWithRecoveryCodesNotUnderKey(String keyId) {
    return database
        .queryOne(
            "SELECT count(DISTINCT subject) FROM recovery_codes WHERE code_hash NOT LIKE ?", row -> row.getLong(1), keyId + ":%")
        .orElse(0L);
  }

  @Override
  public boolean useTotpStep(String subject, long step) {
    // One statement: of two concurrent uses of the same code, only one moves the step forward.
    return database.update(
            "UPDATE totp_credentials SET last_used_step = ? WHERE subject = ? AND last_used_step < ?", step, subject, step)
        == 1;
  }

  @Override
  public void replaceRecoveryCodes(String subject, List<String> codeHashes) {
    database.update("DELETE FROM recovery_codes WHERE subject = ?", subject);
    for (String hash : codeHashes) {
      database.update("INSERT INTO recovery_codes (subject, code_hash) VALUES (?, ?)", subject, hash);
    }
  }

  @Override
  public boolean useRecoveryCode(String subject, String codeHash) {
    return database.update("DELETE FROM recovery_codes WHERE subject = ? AND code_hash = ?", subject, codeHash) == 1;
  }

  @Override
  public int remainingRecoveryCodes(String subject) {
    return database
        .queryOne("SELECT count(*) FROM recovery_codes WHERE subject = ?", row -> row.getInt(1), subject)
        .orElse(0);
  }

  @Override
  public void deleteRecoveryCodes(String subject) {
    database.update("DELETE FROM recovery_codes WHERE subject = ?", subject);
  }

  @Override
  public long accountsWithTotp() {
    return database.queryOne("SELECT count(*) FROM totp_credentials", row -> row.getLong(1)).orElse(0L);
  }
}

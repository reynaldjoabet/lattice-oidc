package com.lattice.oidc.stores.postgres;

import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.models.Passkey;
import com.lattice.oidc.stores.PasskeyStore;
import java.security.SecureRandom;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Singleton;

/** {@link PasskeyStore} in PostgreSQL (tables {@code passkeys}, {@code user_handles}, {@code passkey_offers}). */
@Singleton
public final class PostgresPasskeyStore implements PasskeyStore {

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final String COLUMNS =
      "id, subject, user_handle, public_key_cose, signature_count, name, created_at, last_used_at, backed_up,"
          + " transports::text AS transports";

  private final PostgresDatabase database;

  @Inject
  public PostgresPasskeyStore(PostgresDatabase database) {
    this.database = database;
  }

  private static Passkey passkey(ResultSet row) throws SQLException {
    LinkedHashSet<String> transports = new LinkedHashSet<>();
    Jsons.readList(row.getString("transports")).forEach(transport -> transports.add(String.valueOf(transport)));
    return new Passkey(
        row.getString("id"),
        row.getString("subject"),
        row.getString("user_handle"),
        row.getString("public_key_cose"),
        row.getLong("signature_count"),
        row.getString("name"),
        PostgresDatabase.instant(row, "created_at"),
        Optional.ofNullable(PostgresDatabase.instant(row, "last_used_at")),
        row.getBoolean("backed_up"),
        transports);
  }

  @Override
  public List<Passkey> forSubject(String subject) {
    return database.query(
        "SELECT " + COLUMNS + " FROM passkeys WHERE subject = ? ORDER BY created_at", PostgresPasskeyStore::passkey, subject);
  }

  @Override
  public Optional<Passkey> byId(String credentialId) {
    return credentialId == null
        ? Optional.empty()
        : database.queryOne("SELECT " + COLUMNS + " FROM passkeys WHERE id = ?", PostgresPasskeyStore::passkey, credentialId);
  }

  @Override
  public void save(Passkey passkey) {
    database.update(
        """
        INSERT INTO passkeys (id, subject, user_handle, public_key_cose, signature_count, name, created_at,
                              last_used_at, backed_up, transports)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb)
        ON CONFLICT (id) DO UPDATE SET
          signature_count = EXCLUDED.signature_count, name = EXCLUDED.name,
          last_used_at = EXCLUDED.last_used_at, backed_up = EXCLUDED.backed_up
        """,
        passkey.id(),
        passkey.subject(),
        passkey.userHandle(),
        passkey.publicKeyCose(),
        passkey.signatureCount(),
        passkey.name(),
        passkey.createdAt(),
        passkey.lastUsedAt().orElse(null),
        passkey.backedUp(),
        Jsons.write(passkey.transports()));
  }

  @Override
  public void delete(String credentialId) {
    database.update("DELETE FROM passkeys WHERE id = ?", credentialId);
  }

  @Override
  public String userHandle(String subject) {
    byte[] bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    String candidate = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    // Keeps the existing handle if another request (on any server) created one first.
    database.update(
        "INSERT INTO user_handles (subject, handle) VALUES (?, ?) ON CONFLICT (subject) DO NOTHING", subject, candidate);
    return database
        .queryOne("SELECT handle FROM user_handles WHERE subject = ?", row -> row.getString(1), subject)
        .orElseThrow();
  }

  @Override
  public Optional<String> subjectForUserHandle(String userHandle) {
    return database.queryOne("SELECT subject FROM user_handles WHERE handle = ?", row -> row.getString(1), userHandle);
  }

  @Override
  public Optional<Instant> offeredAt(String subject) {
    return database.queryOne(
        "SELECT offered_at FROM passkey_offers WHERE subject = ?",
        row -> PostgresDatabase.instant(row, "offered_at"),
        subject);
  }

  @Override
  public void markOffered(String subject, Instant at) {
    database.update(
        """
        INSERT INTO passkey_offers (subject, offered_at) VALUES (?, ?)
        ON CONFLICT (subject) DO UPDATE SET offered_at = EXCLUDED.offered_at
        """,
        subject, at);
  }

  @Override
  public long accountsWithPasskeys() {
    return database.queryOne("SELECT count(DISTINCT subject) FROM passkeys", row -> row.getLong(1)).orElse(0L);
  }
}

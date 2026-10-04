package com.lattice.oidc.stores.postgres;

import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.InMemoryUserStore;
import com.lattice.oidc.stores.UserStore;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.Environment;

/**
 * {@link UserStore} in PostgreSQL (table {@code users}). With {@code lattice.demo-users} on, the
 * demo accounts are added only to an empty table, so a real database is never changed.
 */
@Singleton
public final class PostgresUserStore implements UserStore {

  private static final Logger LOG = LoggerFactory.getLogger(PostgresUserStore.class);
  private static final String COLUMNS =
      "subject, login_id, password_hash, claims::text AS claims, attributes::text AS attributes,"
          + " verified_claims::text AS verified_claims";

  private final PostgresDatabase database;

  @Inject
  public PostgresUserStore(PostgresDatabase database, LatticeConfig config, Environment environment) {
    this.database = database;
    if (config.demoUsers() && count() == 0) {
      List<User> demo = InMemoryUserStore.demoUsers(environment);
      demo.forEach(this::save);
      LOG.warn("Seeded {} DEMO user accounts into an empty database; disable lattice.demo-users in production.", demo.size());
    }
  }

  @SuppressWarnings("unchecked")
  private static User user(ResultSet row) throws SQLException {
    return new User(
        row.getString("subject"),
        row.getString("login_id"),
        row.getString("password_hash"),
        Jsons.readMap(row.getString("claims")),
        Jsons.readMap(row.getString("attributes")),
        (List<Map<String, Object>>) (List<?>) Jsons.readList(row.getString("verified_claims")));
  }

  @Override
  public Optional<User> bySubject(String subject) {
    return subject == null
        ? Optional.empty()
        : database.queryOne("SELECT " + COLUMNS + " FROM users WHERE subject = ?", PostgresUserStore::user, subject);
  }

  @Override
  public Optional<User> byLoginId(String loginId) {
    return loginId == null
        ? Optional.empty()
        : database.queryOne(
            "SELECT " + COLUMNS + " FROM users WHERE lower(login_id) = lower(?)", PostgresUserStore::user, loginId);
  }

  @Override
  public Optional<User> byEmail(String email) {
    return email == null
        ? Optional.empty()
        : database.queryOne(
            "SELECT " + COLUMNS + " FROM users WHERE email = lower(?) ORDER BY subject LIMIT 1",
            PostgresUserStore::user,
            email);
  }

  @Override
  public Optional<User> byPhoneNumber(String phoneNumber) {
    return phoneNumber == null
        ? Optional.empty()
        : database.queryOne(
            "SELECT " + COLUMNS + " FROM users WHERE phone_number = ? ORDER BY subject LIMIT 1",
            PostgresUserStore::user,
            phoneNumber);
  }

  @Override
  public void save(User user) {
    database.update(
        """
        INSERT INTO users (subject, login_id, password_hash, claims, attributes, verified_claims)
        VALUES (?, ?, ?, ?::jsonb, ?::jsonb, ?::jsonb)
        ON CONFLICT (subject) DO UPDATE SET
          login_id = EXCLUDED.login_id, password_hash = EXCLUDED.password_hash, claims = EXCLUDED.claims,
          attributes = EXCLUDED.attributes, verified_claims = EXCLUDED.verified_claims, updated_at = now()
        """,
        user.getSubject(),
        user.loginId(),
        user.passwordHash(),
        Jsons.write(user.claims()),
        Jsons.write(user.attributes()),
        Jsons.write(user.verifiedClaims()));
  }

  @Override
  public long count() {
    return database.queryOne("SELECT count(*) FROM users", row -> row.getLong(1)).orElse(0L);
  }
}

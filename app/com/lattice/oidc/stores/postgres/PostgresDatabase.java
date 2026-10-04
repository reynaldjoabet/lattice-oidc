package com.lattice.oidc.stores.postgres;

import com.typesafe.config.Config;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.flywaydb.core.Flyway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.inject.ApplicationLifecycle;

/**
 * The PostgreSQL connection pool ({@code lattice.postgres}). At startup it applies the schema
 * migrations in {@code conf/db/migration} (Flyway), so a new or older database is brought up to
 * date before any request is served.
 *
 * <p>The helpers run one statement each on a pooled connection with auto-commit; every store
 * operation that must be atomic is a single statement. {@link Instant} parameters are sent as
 * {@code timestamptz} and {@link Duration} parameters as seconds.
 */
@Singleton
public final class PostgresDatabase {

  private static final Logger LOG = LoggerFactory.getLogger(PostgresDatabase.class);

  /** Maps the current row of a result. */
  @FunctionalInterface
  public interface Row<T> {
    T map(ResultSet row) throws SQLException;
  }

  private final HikariDataSource dataSource;

  @Inject
  public PostgresDatabase(Config config, ApplicationLifecycle lifecycle) {
    Config postgres = config.getConfig("lattice.postgres");
    HikariConfig hikari = new HikariConfig();
    hikari.setPoolName("lattice-postgres");
    hikari.setJdbcUrl(postgres.getString("url"));
    hikari.setUsername(postgres.getString("username"));
    hikari.setPassword(postgres.getString("password"));
    hikari.setMaximumPoolSize(postgres.getInt("maximum-pool-size"));
    this.dataSource = new HikariDataSource(hikari);
    lifecycle.addStopHook(
        () -> {
          dataSource.close();
          return CompletableFuture.completedFuture(null);
        });
    var result = Flyway.configure().dataSource(dataSource).locations("classpath:db/migration").load().migrate();
    LOG.info("PostgreSQL storage ready (schema version {})", result.targetSchemaVersion);
  }

  /** Runs a query and maps every row. */
  public <T> List<T> query(String sql, Row<T> row, Object... parameters) {
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement = prepare(connection, sql, parameters);
        ResultSet results = statement.executeQuery()) {
      List<T> rows = new ArrayList<>();
      while (results.next()) {
        rows.add(row.map(results));
      }
      return rows;
    } catch (SQLException e) {
      throw new StorageException(sql, e);
    }
  }

  /** Runs a query and maps the first row, if any. */
  public <T> Optional<T> queryOne(String sql, Row<T> row, Object... parameters) {
    List<T> rows = query(sql, row, parameters);
    return rows.isEmpty() ? Optional.empty() : Optional.of(rows.get(0));
  }

  /** Runs an insert, update or delete; returns the number of rows changed. */
  public int update(String sql, Object... parameters) {
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement = prepare(connection, sql, parameters)) {
      return statement.executeUpdate();
    } catch (SQLException e) {
      throw new StorageException(sql, e);
    }
  }

  private static PreparedStatement prepare(Connection connection, String sql, Object... parameters)
      throws SQLException {
    PreparedStatement statement = connection.prepareStatement(sql);
    for (int i = 0; i < parameters.length; i++) {
      Object value = parameters[i];
      if (value instanceof Instant instant) {
        statement.setObject(i + 1, instant.atOffset(ZoneOffset.UTC));
      } else if (value instanceof Duration duration) {
        statement.setDouble(i + 1, duration.toMillis() / 1000.0);
      } else {
        statement.setObject(i + 1, value);
      }
    }
    return statement;
  }

  /** A {@code timestamptz} column as an {@link Instant} (null stays null). */
  public static Instant instant(ResultSet row, String column) throws SQLException {
    OffsetDateTime value = row.getObject(column, OffsetDateTime.class);
    return value == null ? null : value.toInstant();
  }

  /** A failed statement. The SQL is included; parameter values are not, since they may be secret. */
  public static final class StorageException extends RuntimeException {
    StorageException(String sql, SQLException cause) {
      super("PostgreSQL statement failed: " + sql.strip().replaceAll("\\s+", " "), cause);
    }
  }
}

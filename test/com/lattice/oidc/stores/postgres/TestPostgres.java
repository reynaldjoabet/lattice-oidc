package com.lattice.oidc.stores.postgres;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Map;
import java.util.UUID;

/**
 * A real PostgreSQL for the storage tests: one embedded server per test JVM (Zonky's binaries,
 * PostgreSQL 18), and a fresh, empty database for every caller of {@link #newDatabase}. Lattice's own
 * startup then applies the Flyway migrations to it, as in production.
 */
public final class TestPostgres {

  private static EmbeddedPostgres server;

  private TestPostgres() {}

  private static synchronized EmbeddedPostgres server() {
    if (server == null) {
      try {
        server = EmbeddedPostgres.builder().start();
      } catch (IOException e) {
        throw new UncheckedIOException("Could not start the embedded PostgreSQL", e);
      }
      Runtime.getRuntime().addShutdownHook(new Thread(() -> {
        try {
          server.close();
        } catch (IOException ignored) {
          // The JVM is exiting anyway.
        }
      }));
    }
    return server;
  }

  /** Creates an empty database and returns Lattice's configuration for using it. */
  public static Map<String, Object> newDatabase() {
    String name = "lattice_" + UUID.randomUUID().toString().replace("-", "");
    try (Connection connection = server().getPostgresDatabase().getConnection();
        Statement statement = connection.createStatement()) {
      statement.execute("CREATE DATABASE " + name);
    } catch (SQLException e) {
      throw new IllegalStateException("Could not create a test database", e);
    }
    return Map.of(
        "lattice.storage", "postgres",
        "lattice.postgres.url", "jdbc:postgresql://localhost:" + server().getPort() + "/" + name,
        "lattice.postgres.username", "postgres",
        "lattice.postgres.password", "");
  }
}

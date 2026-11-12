package com.lattice.oidc.stores.postgres;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Map;
import java.util.UUID;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * A real PostgreSQL for the storage tests: one Docker container per test JVM (Testcontainers), and
 * a fresh, empty database for every caller of {@link #newDatabase}. Lattice's own startup then
 * applies the Flyway migrations to it, as in production. Needs a running Docker; Testcontainers
 * removes the container when the JVM exits ({@code Test / fork := true} in build.sbt gives each
 * test run its own JVM).
 */
public final class TestPostgres {

  /** The image deploy/compose/compose.yaml runs; change both together. */
  private static final String IMAGE = "postgres:18";

  private static PostgreSQLContainer server;

  private TestPostgres() {}

  private static synchronized PostgreSQLContainer server() {
    if (server == null) {
      if (!DockerClientFactory.instance().isDockerAvailable()) {
        throw new IllegalStateException(
            "The PostgreSQL store tests need Docker, and no Docker daemon answered. Start Docker.");
      }
      PostgreSQLContainer container = new PostgreSQLContainer(IMAGE);
      container.start();
      server = container;
    }
    return server;
  }

  /** Creates an empty database and returns Lattice's configuration for using it. */
  public static Map<String, Object> newDatabase() {
    PostgreSQLContainer server = server();
    String name = "lattice_" + UUID.randomUUID().toString().replace("-", "");
    try (Connection connection =
            DriverManager.getConnection(
                server.getJdbcUrl(), server.getUsername(), server.getPassword());
        Statement statement = connection.createStatement()) {
      statement.execute("CREATE DATABASE " + name);
    } catch (SQLException e) {
      throw new IllegalStateException("Could not create a test database", e);
    }
    String url =
        "jdbc:postgresql://"
            + server.getHost()
            + ":"
            + server.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT)
            + "/"
            + name;
    return Map.of(
        "lattice.storage",
        "postgres",
        "lattice.postgres.url",
        url,
        "lattice.postgres.username",
        server.getUsername(),
        "lattice.postgres.password",
        server.getPassword());
  }
}

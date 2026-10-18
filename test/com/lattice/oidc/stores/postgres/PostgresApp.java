package com.lattice.oidc.stores.postgres;

import static com.lattice.oidc.OidcTestSupport.app;

import com.lattice.oidc.client.FakeAuthleteApi;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import play.Application;
import play.test.Helpers;

/**
 * A started Lattice with {@code lattice.storage = postgres} on a fresh database ({@link TestPostgres}).
 * A test class shares one, and its tests use their own keys ({@link #unique}), so they don't
 * interfere.
 */
final class PostgresApp {

  private PostgresApp() {}

  static Application start() {
    Map<String, Object> config = new HashMap<>(TestPostgres.newDatabase());
    config.put("lattice.demo-users", false);
    Application app = app(new FakeAuthleteApi(), config);
    Helpers.start(app);
    return app;
  }

  static String unique(String prefix) {
    return prefix + "-" + UUID.randomUUID();
  }

  /** Now, at PostgreSQL's precision (microseconds), so it reads back equal. */
  static Instant now() {
    return Instant.now().truncatedTo(ChronoUnit.MICROS);
  }

  /** Rows in a table, including expired ones that the stores' lookups would ignore. */
  static long rows(Application app, String table) {
    return app.injector()
        .instanceOf(PostgresDatabase.class)
        .queryOne("SELECT count(*) FROM " + table, row -> row.getLong(1))
        .orElseThrow();
  }
}

package com.lattice.oidc.cache;

import com.lattice.oidc.stores.postgres.PostgresDatabase;
import com.typesafe.config.Config;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BiConsumer;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.postgresql.PGConnection;
import org.postgresql.PGNotification;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.inject.ApplicationLifecycle;

/**
 * {@link InvalidationBus} over PostgreSQL {@code LISTEN}/{@code NOTIFY}: every server listens on one
 * channel on a dedicated connection. If that connection drops, announcements may be missed, so on
 * reconnecting each server drops its whole cache.
 */
@Singleton
public final class PostgresInvalidationBus implements InvalidationBus {

  private static final Logger LOG = LoggerFactory.getLogger(PostgresInvalidationBus.class);
  static final String CHANNEL = "lattice_cache_invalidation";

  private final PostgresDatabase database;
  private final Config postgres;
  private final List<BiConsumer<String, String>> listeners = new CopyOnWriteArrayList<>();
  private volatile boolean running = true;

  @Inject
  public PostgresInvalidationBus(PostgresDatabase database, Config config, ApplicationLifecycle lifecycle) {
    this.database = database;
    this.postgres = config.getConfig("lattice.postgres");
    Thread listener = Thread.ofVirtual().name("lattice-cache-invalidation").start(this::listen);
    lifecycle.addStopHook(
        () -> {
          running = false;
          listener.interrupt();
          return CompletableFuture.completedFuture(null);
        });
  }

  @Override
  public void publish(String region, String key) {
    database.query("SELECT pg_notify(?, ?)", row -> null, CHANNEL, region + "|" + key);
  }

  @Override
  public void subscribe(BiConsumer<String, String> listener) {
    listeners.add(listener);
  }

  private void listen() {
    boolean reconnecting = false;
    while (running) {
      try (Connection connection =
          DriverManager.getConnection(
              postgres.getString("url"), postgres.getString("username"), postgres.getString("password"))) {
        try (Statement statement = connection.createStatement()) {
          statement.execute("LISTEN " + CHANNEL);
        }
        if (reconnecting) {
          // Announcements made while disconnected were missed: start from an empty cache.
          deliver(null, null);
          LOG.info("Cache invalidation listener reconnected; cache cleared");
        }
        PGConnection notifications = connection.unwrap(PGConnection.class);
        while (running) {
          PGNotification[] received = notifications.getNotifications(1_000);
          if (received != null) {
            for (PGNotification notification : received) {
              String payload = notification.getParameter();
              int separator = payload.indexOf('|');
              if (separator > 0) {
                deliver(payload.substring(0, separator), payload.substring(separator + 1));
              }
            }
          }
        }
      } catch (SQLException e) {
        if (!running) {
          return;
        }
        LOG.warn("Cache invalidation listener disconnected: {}", e.getMessage());
        reconnecting = true;
        try {
          Thread.sleep(1_000);
        } catch (InterruptedException interrupted) {
          return;
        }
      }
    }
  }

  private void deliver(String region, String key) {
    listeners.forEach(listener -> listener.accept(region, key));
  }
}

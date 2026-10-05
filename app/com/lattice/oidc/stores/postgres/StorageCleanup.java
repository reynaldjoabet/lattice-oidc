package com.lattice.oidc.stores.postgres;

import com.lattice.oidc.client.AuthleteExecutionContext;
import com.lattice.oidc.common.LatticeConfig;
import com.typesafe.config.Config;
import java.time.Duration;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.apache.pekko.actor.ActorSystem;
import org.apache.pekko.actor.Cancellable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.inject.ApplicationLifecycle;

/**
 * Deletes expired rows every {@code lattice.postgres.cleanup-interval}: short-lived entries,
 * counters, consents past their keep date, audit events past {@code lattice.audit.retention}, and
 * sessions past their lifetime or idle for longer than
 * {@code lattice.session.idle-timeout}. Every server runs it; the deletes are idempotent, so running
 * it on several servers at once is harmless. Lookups already ignore expired rows, so the cleanup
 * only reclaims space.
 */
@Singleton
public final class StorageCleanup {

  private static final Logger LOG = LoggerFactory.getLogger(StorageCleanup.class);

  private final PostgresDatabase database;
  private final LatticeConfig config;
  private final Duration auditRetention;

  @Inject
  public StorageCleanup(
      PostgresDatabase database,
      LatticeConfig config,
      Config rawConfig,
      ActorSystem actorSystem,
      AuthleteExecutionContext executionContext,
      ApplicationLifecycle lifecycle) {
    this.database = database;
    this.config = config;
    this.auditRetention = rawConfig.getDuration("lattice.audit.retention");
    Duration interval = rawConfig.getDuration("lattice.postgres.cleanup-interval");
    Cancellable task = actorSystem.scheduler().scheduleAtFixedRate(interval, interval, this::run, executionContext);
    lifecycle.addStopHook(
        () -> {
          task.cancel();
          return java.util.concurrent.CompletableFuture.completedFuture(null);
        });
  }

  void run() {
    try {
      int entries = database.update("DELETE FROM ephemeral WHERE expires_at <= now()");
      int counters = database.update("DELETE FROM counters WHERE window_ends_at <= now()");
      int consents = database.update("DELETE FROM obb_consents WHERE keep_until <= now()");
      database.update("DELETE FROM audit_events WHERE occurred_at <= now() - make_interval(secs => ?)", auditRetention);
      // Idle limits differ for "keep me signed in" sessions; zero means no idle limit.
      Duration idle = config.sessionIdleTimeout();
      Duration rememberedIdle = config.rememberMe().idleTimeout();
      int sessions =
          database.update(
              """
              DELETE FROM sessions WHERE expires_at <= now()
                OR (NOT remember_me AND ? > 0 AND last_seen_at <= now() - make_interval(secs => ?))
                OR (remember_me AND ? > 0 AND last_seen_at <= now() - make_interval(secs => ?))
              """,
              idle, idle, rememberedIdle, rememberedIdle);
      if (entries + counters + consents + sessions > 0) {
        LOG.debug("Storage cleanup: {} entries, {} counters, {} consents, {} sessions", entries, counters, consents, sessions);
      }
    } catch (RuntimeException e) {
      LOG.warn("Storage cleanup failed: {}", e.getMessage());
    }
  }
}

package com.lattice.oidc.client;

import com.lattice.oidc.metrics.Metrics;
import com.typesafe.config.Config;
import io.micrometer.core.instrument.Gauge;
import java.util.concurrent.atomic.AtomicInteger;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.apache.pekko.actor.ActorSystem;
import play.libs.concurrent.CustomExecutionContext;

/**
 * Executor for blocking Authlete calls (the {@code authlete-dispatcher} pool). Controllers must run
 * Authlete calls here, never on Play's default dispatcher.
 *
 * <p>Tasks waiting for a thread and tasks running are gauges ({@code lattice_authlete_executor_tasks}),
 * next to the pool size: a queue that grows while every thread is busy means the pool is saturated.
 */
@Singleton
public final class AuthleteExecutionContext extends CustomExecutionContext {

  private static final String POOL_SIZE = "authlete-dispatcher.thread-pool-executor.fixed-pool-size";

  private final AtomicInteger queued = new AtomicInteger();
  private final AtomicInteger active = new AtomicInteger();

  @Inject
  public AuthleteExecutionContext(ActorSystem actorSystem, Config config, Metrics metrics) {
    super(actorSystem, "authlete-dispatcher");
    Gauge.builder("lattice.authlete.executor.tasks", queued, AtomicInteger::get)
        .description("Tasks on the Authlete thread pool")
        .tag("state", "queued")
        .register(metrics.registry());
    Gauge.builder("lattice.authlete.executor.tasks", active, AtomicInteger::get)
        .description("Tasks on the Authlete thread pool")
        .tag("state", "active")
        .register(metrics.registry());
    if (config.hasPath(POOL_SIZE)) {
      int threads = config.getInt(POOL_SIZE);
      Gauge.builder("lattice.authlete.executor.threads", () -> threads)
          .description("Threads in the Authlete thread pool")
          .register(metrics.registry());
    }
  }

  @Override
  public void execute(Runnable task) {
    queued.incrementAndGet();
    try {
      super.execute(
          () -> {
            queued.decrementAndGet();
            active.incrementAndGet();
            try {
              task.run();
            } finally {
              active.decrementAndGet();
            }
          });
    } catch (RuntimeException e) {
      queued.decrementAndGet();
      throw e;
    }
  }
}

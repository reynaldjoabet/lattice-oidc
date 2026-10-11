package com.lattice.oidc.client;

import com.lattice.oidc.metrics.Metrics;
import com.typesafe.config.Config;
import io.micrometer.core.instrument.Gauge;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.apache.pekko.actor.ActorSystem;
import play.libs.concurrent.CustomExecutionContext;

/**
 * Executor for blocking Authlete calls (the {@code authlete-dispatcher}). Controllers must run
 * Authlete calls here, never on Play's default dispatcher.
 *
 * <p>Each call blocks while it waits for Authlete (tens of milliseconds), so with a fixed pool of 32
 * threads a server could make at most 32 / 0.025 s, about 1,300 Authlete calls a second, however fast
 * everything else was. The dispatcher therefore runs every task on its own <b>virtual thread</b>
 * (a thread that waits costs almost nothing), and what limits concurrency is {@code
 * authlete.max-concurrent-calls}: the number of calls in flight to Authlete at once, which protects
 * Authlete and the connection pool. Further tasks wait for a permit. On a JVM without virtual threads
 * (before 21) the dispatcher falls back to the fixed pool, and the limit then rarely matters.
 *
 * <p>Tasks waiting for a permit and tasks running are gauges ({@code
 * lattice_authlete_executor_tasks}), next to the limit: a queue that keeps growing while the active
 * count sits at the limit means the limit is too low for the load, or Authlete is slow.
 */
@Singleton
public final class AuthleteExecutionContext extends CustomExecutionContext {

  private static final String POOL_SIZE = "authlete-dispatcher.thread-pool-executor.fixed-pool-size";
  private static final String MAX_CONCURRENT = "authlete.max-concurrent-calls";

  private final AtomicInteger queued = new AtomicInteger();
  private final AtomicInteger active = new AtomicInteger();

  /** One permit per call in flight to Authlete (and per other blocking task: webhooks, cleanup). */
  private final Semaphore permits;

  @Inject
  public AuthleteExecutionContext(ActorSystem actorSystem, Config config, Metrics metrics) {
    super(actorSystem, "authlete-dispatcher");
    int limit = config.hasPath(MAX_CONCURRENT) ? config.getInt(MAX_CONCURRENT) : 1000;
    if (limit < 1) {
      throw new IllegalArgumentException(MAX_CONCURRENT + " must be at least 1: " + limit);
    }
    this.permits = new Semaphore(limit, true);
    Gauge.builder("lattice.authlete.executor.limit", () -> limit)
        .description("Calls to Authlete allowed at once (authlete.max-concurrent-calls)")
        .register(metrics.registry());
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
            // Waits for a permit; on a virtual thread this costs almost nothing. Not interruptible: a
            // task that gave up here would never complete the request that is waiting for it.
            permits.acquireUninterruptibly();
            queued.decrementAndGet();
            active.incrementAndGet();
            try {
              task.run();
            } finally {
              active.decrementAndGet();
              permits.release();
            }
          });
    } catch (RuntimeException e) {
      queued.decrementAndGet();
      throw e;
    }
  }
}

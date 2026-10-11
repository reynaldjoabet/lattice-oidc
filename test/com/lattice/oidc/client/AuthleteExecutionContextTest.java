package com.lattice.oidc.client;

import static com.lattice.oidc.OidcTestSupport.app;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Test;
import play.Application;
import play.test.Helpers;

/**
 * The executor for blocking Authlete calls runs each call on a virtual thread, so that waiting for
 * Authlete does not use up a pool; what limits concurrency is {@code authlete.max-concurrent-calls}.
 */
public class AuthleteExecutionContextTest {

  /** Runs {@code tasks} sleeping tasks on the context of an application with the given limit. */
  private static int peakConcurrency(int limit, int tasks, AtomicBoolean allVirtual) throws Exception {
    Application app = app(new FakeAuthleteApi(), Map.of("authlete.max-concurrent-calls", limit));
    Helpers.start(app);
    try {
      AuthleteExecutionContext context = app.injector().instanceOf(AuthleteExecutionContext.class);
      AtomicInteger running = new AtomicInteger();
      AtomicInteger peak = new AtomicInteger();
      List<CompletableFuture<Void>> done = new ArrayList<>();
      for (int i = 0; i < tasks; i++) {
        done.add(
            CompletableFuture.runAsync(
                () -> {
                  if (!Thread.currentThread().isVirtual()) {
                    allVirtual.set(false);
                  }
                  peak.accumulateAndGet(running.incrementAndGet(), Math::max);
                  try {
                    Thread.sleep(40); // a call waiting for Authlete
                  } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                  }
                  running.decrementAndGet();
                },
                context));
      }
      for (CompletableFuture<Void> task : done) {
        task.get(20, TimeUnit.SECONDS);
      }
      return peak.get();
    } finally {
      Helpers.stop(app);
    }
  }

  @Test
  public void noMoreThanTheLimitRunAtOnce() throws Exception {
    assertEquals(3, peakConcurrency(3, 24, new AtomicBoolean(true)));
  }

  /** Far more waiting calls than the 32 threads of the old fixed pool run at the same time. */
  @Test
  public void waitingCallsAreNotLimitedByAPoolSize() throws Exception {
    AtomicBoolean allVirtual = new AtomicBoolean(true);
    int peak = peakConcurrency(200, 200, allVirtual);
    assertTrue("peak concurrency " + peak, peak > 100);
    assertTrue("every task ran on a virtual thread", allVirtual.get());
  }
}

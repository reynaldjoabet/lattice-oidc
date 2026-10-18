package com.lattice.oidc.stores.postgres;

import static com.lattice.oidc.stores.postgres.PostgresApp.unique;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.lattice.oidc.stores.CounterStore;
import com.lattice.oidc.stores.EphemeralStore;
import com.lattice.oidc.stores.EphemeralStore.Entry;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import play.Application;
import play.test.Helpers;

/** Single-use state and rate-limit counters in PostgreSQL ({@code lattice.short-lived-state = storage}). */
public class PostgresShortLivedStoresTest {

  private static Application app;
  private static EphemeralStore entries;
  private static CounterStore counters;

  @BeforeClass
  public static void start() {
    app = PostgresApp.start();
    entries = app.injector().instanceOf(EphemeralStore.class);
    counters = app.injector().instanceOf(CounterStore.class);
  }

  @AfterClass
  public static void stop() {
    Helpers.stop(app);
  }

  private static final Duration LONG = Duration.ofMinutes(5);

  /** Runs {@code task} on {@code threads} threads at once and returns their results. */
  private static <T> List<T> concurrently(int threads, Callable<T> task) throws Exception {
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    try {
      List<Future<T>> futures = new ArrayList<>();
      for (int i = 0; i < threads; i++) {
        futures.add(pool.submit(task));
      }
      List<T> results = new ArrayList<>();
      for (Future<T> future : futures) {
        results.add(future.get());
      }
      return results;
    } finally {
      pool.shutdownNow();
    }
  }

  // ------------------------------------------------------------------------------ entries

  @Test
  public void anEntryReadsBackAndIsReplacedByTheSameKey() {
    String ns = unique("ns");
    entries.put(ns, "k", "owner-1", "sub-1", "{\"a\":1}", LONG);
    Entry entry = entries.get(ns, "k").orElseThrow();
    assertEquals("owner-1", entry.owner());
    assertEquals("sub-1", entry.subject());
    assertEquals(Map.of("a", 1), com.lattice.oidc.common.JsonHelpers.readMap(entry.json()));

    entries.put(ns, "k", "owner-2", null, "{\"b\":2}", LONG);
    Entry replaced = entries.get(ns, "k").orElseThrow();
    assertEquals("owner-2", replaced.owner());
    assertEquals(null, replaced.subject());
    assertEquals(Map.of("b", 2), com.lattice.oidc.common.JsonHelpers.readMap(replaced.json()));
  }

  @Test
  public void anExpiredEntryIsNotFound() throws Exception {
    String ns = unique("ns");
    entries.put(ns, "k", null, null, "{}", Duration.ofMillis(50));
    Thread.sleep(150);
    assertEquals(Optional.empty(), entries.get(ns, "k"));
    assertEquals(Optional.empty(), entries.take(ns, "k"));
    assertEquals(0, entries.count(ns));
  }

  @Test
  public void anEntryCanBeTakenOnlyOnceEvenConcurrently() throws Exception {
    String ns = unique("ns");
    entries.put(ns, "code", null, null, "{}", LONG);
    List<Optional<Entry>> taken = concurrently(8, () -> entries.take(ns, "code"));
    assertEquals("exactly one caller receives the entry", 1, taken.stream().filter(Optional::isPresent).count());
    assertEquals(Optional.empty(), entries.get(ns, "code"));
  }

  @Test
  public void entriesAreListedAndDeletedBySubject() {
    String ns = unique("ns");
    entries.put(ns, "later", null, "alice", "{}", Duration.ofMinutes(9));
    entries.put(ns, "sooner", null, "alice", "{}", Duration.ofMinutes(3));
    entries.put(ns, "bob", null, "bob", "{}", LONG);
    assertEquals(List.of("sooner", "later"), entries.bySubject(ns, "alice").stream().map(Entry::key).toList());
    assertEquals(2, entries.deleteBySubject(ns, "alice"));
    assertEquals(List.of(), entries.bySubject(ns, "alice"));
    assertEquals(1, entries.count(ns));
  }

  @Test
  public void anEntryCanBeDeleted() {
    String ns = unique("ns");
    entries.put(ns, "k", null, null, "{}", LONG);
    entries.delete(ns, "k");
    assertEquals(Optional.empty(), entries.get(ns, "k"));
  }

  @Test
  public void liveEntriesAreCountedPerNamespace() {
    String a = unique("a");
    String b = unique("b");
    entries.put(a, "1", null, null, "{}", LONG);
    entries.put(a, "2", null, null, "{}", LONG);
    entries.put(b, "1", null, null, "{}", LONG);
    Map<String, Long> counts = entries.counts();
    assertEquals(Long.valueOf(2), counts.get(a));
    assertEquals(Long.valueOf(1), counts.get(b));
  }

  // ----------------------------------------------------------------------------- counters

  @Test
  public void aCounterCountsWithinItsWindow() {
    String key = unique("login");
    assertEquals(1, counters.increment(key, LONG));
    assertEquals(2, counters.increment(key, LONG));
    assertEquals(3, counters.increment(key, LONG));
    assertEquals(3, counters.count(key));
  }

  @Test
  public void anEndedWindowStartsOver() throws Exception {
    String key = unique("login");
    counters.increment(key, Duration.ofMillis(50));
    counters.increment(key, Duration.ofMillis(50));
    Thread.sleep(150);
    assertEquals("an ended window doesn't count", 0, counters.count(key));
    assertEquals("and the next increment starts at 1", 1, counters.increment(key, LONG));
  }

  @Test
  public void concurrentIncrementsAllCount() throws Exception {
    String key = unique("spray");
    List<Long> results = concurrently(20, () -> counters.increment(key, LONG));
    assertEquals(20, counters.count(key));
    assertEquals("each caller saw a distinct count", 20, results.stream().distinct().count());
  }

  @Test
  public void countersAreResetOneByOneOrByPrefix() {
    String prefix = unique("p") + ":";
    counters.increment(prefix + "a", LONG);
    counters.increment(prefix + "b", LONG);
    counters.increment(prefix + "b", LONG);
    counters.reset(prefix + "a");
    assertEquals(0, counters.count(prefix + "a"));
    assertEquals(2, counters.count(prefix + "b"));
    counters.resetPrefix(prefix);
    assertEquals(0, counters.count(prefix + "b"));
  }

  @Test
  public void countersAtOrAboveAMinimumAreCountedByPrefix() {
    String prefix = unique("p") + ":";
    counters.increment(prefix + "one", LONG);
    for (int i = 0; i < 3; i++) {
      counters.increment(prefix + "three", LONG);
    }
    for (int i = 0; i < 5; i++) {
      counters.increment(prefix + "five", LONG);
    }
    assertEquals(2, counters.countAtLeast(prefix, 3));
    assertEquals(3, counters.countAtLeast(prefix, 1));
    assertTrue(counters.countAtLeast(prefix, 6) == 0);
  }
}

package com.lattice.oidc.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.After;
import org.junit.Test;

/** Password checks and hashes, and the limit on how many run at once. */
public class PasswordHasherTest {

  @After
  public void restore() {
    PasswordHasher.configure(PasswordHasher.defaultConcurrency());
  }

  @Test
  public void aHashChecksItsPasswordOnly() {
    String hash = PasswordHasher.hash("correct horse battery staple");
    assertTrue(PasswordHasher.check("correct horse battery staple", hash));
    assertFalse(PasswordHasher.check("wrong", hash));
  }

  @Test
  public void noMoreThanTheLimitRunAtOnce() throws Exception {
    PasswordHasher.configure(2);
    String hash = PasswordHasher.hash("secret");
    AtomicInteger running = new AtomicInteger();
    AtomicInteger peak = new AtomicInteger();
    // A real Argon2 check inside the limited section, counting how many run at the same moment.
    ExecutorService pool = Executors.newFixedThreadPool(8);
    List<Future<Boolean>> results = new ArrayList<>();
    for (int i = 0; i < 16; i++) {
      results.add(
          pool.submit(
              () ->
                  PasswordHasher.limited(
                      () -> {
                        peak.accumulateAndGet(running.incrementAndGet(), Math::max);
                        try {
                          return com.password4j.Password.check("secret", hash).withArgon2();
                        } finally {
                          running.decrementAndGet();
                        }
                      })));
    }
    for (Future<Boolean> result : results) {
      assertTrue(result.get());
    }
    pool.shutdown();
    assertEquals("at most 2 at a time", 2, peak.get());
  }

  @Test(expected = IllegalArgumentException.class)
  public void theLimitIsAtLeastOne() {
    PasswordHasher.configure(0);
  }
}

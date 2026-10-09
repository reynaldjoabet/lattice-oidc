package com.lattice.oidc.security;

import com.password4j.Password;
import java.util.concurrent.Semaphore;

/**
 * Every Argon2 check and hash in Lattice goes through here, and at most {@link #concurrency()} run at
 * once; the others wait their turn.
 *
 * <p>Argon2 is memory-hard on purpose: each check fills a large block of memory, and its speed is
 * limited by memory bandwidth more than by CPU cores (on an 8-core machine, checks per second barely
 * rise past 4 threads). Without a limit, a burst of sign-ins (or an attacker sending wrong passwords)
 * runs one hash per request thread at once: memory use jumps with the number of threads, every check
 * gets slower, and the rest of the server is starved. With a limit, memory use is bounded and each
 * check runs at full speed; requests queue instead.
 *
 * <p>The limit is {@code lattice.login.hashing-concurrency} (default: the number of CPU cores), set
 * at startup by {@link LoginService}.
 */
public final class PasswordHasher {

  private static volatile Semaphore permits = new Semaphore(defaultConcurrency(), true);
  private static volatile int concurrency = defaultConcurrency();

  private PasswordHasher() {}

  static int defaultConcurrency() {
    return Math.max(1, Runtime.getRuntime().availableProcessors());
  }

  /** Sets the limit; called once at startup. Checks already waiting keep the previous limit. */
  static void configure(int limit) {
    if (limit < 1) {
      throw new IllegalArgumentException("lattice.login.hashing-concurrency must be at least 1: " + limit);
    }
    concurrency = limit;
    permits = new Semaphore(limit, true);
  }

  public static int concurrency() {
    return concurrency;
  }

  /** Whether {@code password} matches the Argon2 {@code hash}. */
  public static boolean check(String password, String hash) {
    return limited(() -> Password.check(password, hash).withArgon2());
  }

  /** A new Argon2 hash of {@code password}, with a random salt. */
  public static String hash(String password) {
    return limited(() -> Password.hash(password).addRandomSalt().withArgon2().getResult());
  }

  /** Runs {@code work} within the limit (package-private for the test). */
  static <T> T limited(java.util.function.Supplier<T> work) {
    Semaphore current = permits;
    try {
      current.acquire();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("Interrupted while waiting to check a password", e);
    }
    try {
      return work.get();
    } finally {
      current.release();
    }
  }
}

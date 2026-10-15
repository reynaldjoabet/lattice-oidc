package com.lattice.oidc.security;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.Semaphore;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

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
 *
 * <p><b>Format and compatibility.</b> Hashes are Argon2id in the standard PHC string format,
 * {@code $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>} (Base64 without padding), by default with 19
 * MiB of memory and two passes: the minimum OWASP's password storage guidance lists for Argon2id (19 MiB, two
 * passes, one lane). A check takes its parameters from the stored string, so a hash made with other
 * parameters, or by another implementation of the standard (this class replaced password4j, which
 * writes the same format), still verifies.
 *
 * <p><b>Raising the cost.</b> The cost of new hashes is configuration ({@code lattice.login.argon2},
 * see {@link Cost}), set at startup by {@link LoginService}; the default is the one above. Existing
 * hashes keep verifying with their own parameters, and {@link #needsRehash} tells {@link
 * LoginService} to replace a weaker one when its owner next signs in (it cannot be done any other way:
 * a hash cannot be recomputed from itself). A cost below OWASP's minimum is refused at startup, so a
 * typo cannot quietly make every new hash weak.
 *
 * <p><b>Going back to password4j.</b> Its {@code check(...).withArgon2()} does not read the memory size
 * from the hash: it uses its own default (15 MiB), so it cannot verify a hash that was upgraded to
 * 19 MiB (a test pins this). A rollback to the old code therefore needs {@code hash.argon2.memory=19456}
 * in password4j's {@code psw4j.properties} first, or accounts that have already signed in since the
 * upgrade would be locked out until they reset their password.
 *
 * <p><b>Why Bouncy Castle.</b> With the same parameters it was about 1.4 times faster on one thread
 * and 1.6 times faster on eight than password4j's Argon2 (202 against 124 hashes per second on an
 * 8-core Apple M1), and it is already a dependency. This is the cost of a sign-in, so it is the
 * ceiling of password sign-ins per server, and it is deliberately high: the same cost is what an
 * attacker with a stolen database pays for every guess.
 */
public final class PasswordHasher {

  /**
   * The cost of new hashes: memory in KiB (Argon2's unit), passes over it, and lanes. Hashes made with
   * less memory or fewer passes are upgraded when their owner signs in.
   *
   * <p>Must meet at least one of the Argon2id minimums in OWASP's Password Storage Cheat Sheet, which
   * it lists as equally strong: 46 MiB and 1 pass, 19 MiB and 2, 12 MiB and 3, 9 MiB and 4, or 7 MiB
   * and 5 (as much memory and as many passes, or more). It must also stay within what a stored hash
   * may ask for ({@link #MAX_MEMORY_KIB} and friends), or new hashes would never verify.
   */
  public record Cost(int memoryKib, int iterations, int parallelism) {

    /** OWASP's minimums, as {memory KiB, passes}. Declared first: {@link #DEFAULT} is checked against it. */
    private static final int[][] OWASP_MINIMUMS = {{47_104, 1}, {19_456, 2}, {12_288, 3}, {9_216, 4}, {7_168, 5}};

    /** 19 MiB, two passes, one lane. */
    public static final Cost DEFAULT = new Cost(19_456, 2, 1);

    public Cost {
      if (parallelism < 1 || parallelism > MAX_PARALLELISM) {
        throw new IllegalArgumentException("lattice.login.argon2.parallelism must be 1 to " + MAX_PARALLELISM + ": " + parallelism);
      }
      if (memoryKib > MAX_MEMORY_KIB || iterations > MAX_ITERATIONS) {
        throw new IllegalArgumentException(
            "lattice.login.argon2 asks for more than a stored hash may ("
                + MAX_MEMORY_KIB + " KiB, " + MAX_ITERATIONS + " passes): m=" + memoryKib + ", t=" + iterations);
      }
      boolean meetsAMinimum = false;
      for (int[] minimum : OWASP_MINIMUMS) {
        meetsAMinimum |= memoryKib >= minimum[0] && iterations >= minimum[1];
      }
      if (!meetsAMinimum || memoryKib < 8 * parallelism) {
        throw new IllegalArgumentException(
            "lattice.login.argon2 is below OWASP's Argon2id minimum (for example 19456 KiB and 2 passes): m="
                + memoryKib + ", t=" + iterations + ", p=" + parallelism);
      }
    }
  }

  static final int SALT_BYTES = 16;
  static final int HASH_BYTES = 32;

  /**
   * Bounds on what a stored hash may ask for. They exist so that a corrupt or hostile string in a
   * user record cannot make one check allocate gigabytes or run for minutes: it is refused, as a
   * wrong password.
   */
  private static final int MAX_MEMORY_KIB = 262_144;

  private static final int MAX_ITERATIONS = 20;
  private static final int MAX_PARALLELISM = 32;

  /** {@code $argon2id$v=19$m=19456,t=2,p=1$salt$hash}; the version is optional (then 16, per the PHC format). */
  private static final Pattern PHC =
      Pattern.compile(
          "\\$(argon2id|argon2i|argon2d)\\$(?:v=(\\d+)\\$)?m=(\\d+),t=(\\d+),p=(\\d+)\\$([A-Za-z0-9+/]+={0,2})\\$([A-Za-z0-9+/]+={0,2})");

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final Base64.Encoder BASE64 = Base64.getEncoder().withoutPadding();

  private static volatile Cost cost = Cost.DEFAULT;
  private static volatile Semaphore slots = new Semaphore(defaultConcurrency(), true);
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
    slots = new Semaphore(limit, true);
  }

  public static int concurrency() {
    return concurrency;
  }

  /** Sets the cost of new hashes; called once at startup. */
  static void configure(Cost newCost) {
    cost = java.util.Objects.requireNonNull(newCost);
  }

  /** The cost new hashes get. */
  public static Cost cost() {
    return cost;
  }

  /**
   * Whether {@code password} matches the Argon2 {@code hash}. A hash that is malformed, or that asks
   * for more memory or time than {@link #MAX_MEMORY_KIB} and friends allow, never matches (and does
   * not throw: a corrupt record must not turn every sign-in into a server error).
   */
  public static boolean check(String password, String hash) {
    if (password == null) {
      return false;
    }
    Stored stored = Stored.parse(hash);
    if (stored == null) {
      return false;
    }
    return limited(
        () -> {
          byte[] actual =
              argon2(stored.type, stored.version, stored.memoryKib, stored.iterations, stored.parallelism, stored.salt, stored.hash.length, password);
          return MessageDigest.isEqual(actual, stored.hash);
        });
  }

  /**
   * Whether {@code hash} is weaker than what a new hash gets today: another Argon2 type or version, less
   * memory, fewer passes, or a shorter output. A hash that asks for more than today's cost is left
   * alone, so raising the cost by configuration is never undone, and a malformed hash is not "upgraded"
   * (there is nothing to verify it against).
   *
   * <p>Used after a successful sign-in, when the password is at hand: that is the only time a hash can
   * be replaced, because it cannot be computed from the old hash.
   */
  public static boolean needsRehash(String hash) {
    Stored stored = Stored.parse(hash);
    Cost current = cost;
    return stored != null
        && (stored.type != Argon2Parameters.ARGON2_id
            || stored.version != Argon2Parameters.ARGON2_VERSION_13
            || stored.memoryKib < current.memoryKib()
            || stored.iterations < current.iterations()
            || stored.hash.length < HASH_BYTES);
  }

  /** A new Argon2id hash of {@code password}, with a random salt. */
  public static String hash(String password) {
    Cost current = cost;
    byte[] salt = new byte[SALT_BYTES];
    RANDOM.nextBytes(salt);
    byte[] hash =
        limited(
            () ->
                argon2(
                    Argon2Parameters.ARGON2_id,
                    Argon2Parameters.ARGON2_VERSION_13,
                    current.memoryKib(),
                    current.iterations(),
                    current.parallelism(),
                    salt,
                    HASH_BYTES,
                    password));
    return "$argon2id$v=19$m=" + current.memoryKib() + ",t=" + current.iterations() + ",p=" + current.parallelism() + "$" + BASE64.encodeToString(salt) + "$" + BASE64.encodeToString(hash);
  }

  /** The password's UTF-8 bytes go in unchanged: no normalisation, as in the standard. */
  private static byte[] argon2(
      int type, int version, int memoryKib, int iterations, int parallelism, byte[] salt, int length, String password) {
    Argon2Parameters parameters =
        new Argon2Parameters.Builder(type)
            .withVersion(version)
            .withMemoryAsKB(memoryKib)
            .withIterations(iterations)
            .withParallelism(parallelism)
            .withSalt(salt)
            .build();
    Argon2BytesGenerator generator = new Argon2BytesGenerator();
    generator.init(parameters);
    byte[] out = new byte[length];
    generator.generateBytes(password.toCharArray(), out);
    return out;
  }

  /** A parsed, bounds-checked stored hash. */
  private record Stored(int type, int version, int memoryKib, int iterations, int parallelism, byte[] salt, byte[] hash) {

    /** The stored hash, or null if it is malformed or asks for more than the bounds allow. */
    static Stored parse(String text) {
      if (text == null) {
        return null;
      }
      Matcher m = PHC.matcher(text);
      if (!m.matches()) {
        return null;
      }
      try {
        int type =
            switch (m.group(1)) {
              case "argon2id" -> Argon2Parameters.ARGON2_id;
              case "argon2i" -> Argon2Parameters.ARGON2_i;
              default -> Argon2Parameters.ARGON2_d;
            };
        int version = m.group(2) == null ? Argon2Parameters.ARGON2_VERSION_10 : Integer.parseInt(m.group(2));
        if (version != Argon2Parameters.ARGON2_VERSION_10 && version != Argon2Parameters.ARGON2_VERSION_13) {
          return null;
        }
        int memory = Integer.parseInt(m.group(3));
        int iterations = Integer.parseInt(m.group(4));
        int parallelism = Integer.parseInt(m.group(5));
        if (memory < 8 * parallelism || memory > MAX_MEMORY_KIB
            || iterations < 1 || iterations > MAX_ITERATIONS
            || parallelism < 1 || parallelism > MAX_PARALLELISM) {
          return null;
        }
        byte[] salt = Base64.getDecoder().decode(m.group(6));
        byte[] hash = Base64.getDecoder().decode(m.group(7));
        if (salt.length < 8 || hash.length < 4 || hash.length > 128) {
          return null;
        }
        return new Stored(type, version, memory, iterations, parallelism, salt, hash);
      } catch (IllegalArgumentException e) {
        return null; // a number out of range, or bad Base64
      }
    }
  }

  /** Runs {@code work} within the limit (package-private for the test). */
  static <T> T limited(java.util.function.Supplier<T> work) {
    Semaphore current = slots;
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

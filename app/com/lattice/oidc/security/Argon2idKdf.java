package com.lattice.oidc.security;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.Semaphore;
import java.util.function.ToLongFunction;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Derives an encryption key from a password with Argon2id (RFC 9106), for example to encrypt data
 * that only its owner's password should unlock. Checking sign-in passwords is a different job, done
 * by {@link PasswordHasher}.
 *
 * <p><b>Storing what was used.</b> The salt ({@link #newSalt}) and the parameters ({@link
 * Params#encode}, a self-describing string such as {@code $argon2id$v=19$m=65536,t=3,p=1}) must be
 * stored next to the encrypted data: the same password, salt and parameters give the same key, and
 * nothing else does. {@link Params#decode} refuses a stored string it cannot honour exactly, rather
 * than adjusting it: an adjusted parameter derives a different key, so the data would silently become
 * undecryptable.
 *
 * <p><b>Memory.</b> Each derivation fills {@code memoryKib} of memory, by design. Derivations share a
 * memory budget (by default a quarter of the maximum heap): one that would exceed it waits until
 * others finish, so a burst of requests queues instead of exhausting the heap. Parameters larger than
 * the whole budget are refused, since they could never run.
 *
 * <p><b>Choosing the cost.</b> {@link #calibrate} picks the most memory, from {@link Params#DEFAULT}
 * up to the budget, that derives within a target time on this machine. Store the result with each
 * new key; {@link Params#isWeakerThan} tells when a stored key deserves re-deriving (possible only
 * when the password is at hand, as at unlock).
 */
public final class Argon2idKdf {

  /** Salt length for new keys: 128 bits, as RFC 9106 recommends. Shorter stored salts are refused. */
  public static final int SALT_BYTES = 16;

  private static final int MAX_SALT_BYTES = 64;
  private static final int MIN_KEY_BYTES = 16;
  private static final int MAX_KEY_BYTES = 64;

  /**
   * Argon2id parameters: memory in KiB (Argon2's unit), passes over it, and lanes.
   *
   * <p>Must meet at least one of OWASP's Argon2id minimums (46 MiB and 1 pass, 19 MiB and 2, 12 MiB
   * and 3, 9 MiB and 4, or 7 MiB and 5), and stay within bounds that keep a hostile or corrupt stored
   * value from making one derivation allocate gigabytes or run for minutes.
   */
  public record Params(int memoryKib, int iterations, int parallelism) {

    private static final int[][] OWASP_MINIMUMS = {{47_104, 1}, {19_456, 2}, {12_288, 3}, {9_216, 4}, {7_168, 5}};

    /** 1 GiB. */
    public static final int MAX_MEMORY_KIB = 1_048_576;

    public static final int MAX_ITERATIONS = 10;
    public static final int MAX_PARALLELISM = 16;

    /**
     * 64 MiB and three passes: RFC 9106's recommendation where memory is limited (§4), with one lane
     * because this implementation computes lanes one after another, so more lanes cost time and gain
     * nothing.
     */
    public static final Params DEFAULT = new Params(65_536, 3, 1);

    private static final Pattern ENCODED = Pattern.compile("\\$argon2id\\$v=19\\$m=(\\d{1,8}),t=(\\d{1,3}),p=(\\d{1,3})");

    public Params {
      if (memoryKib > MAX_MEMORY_KIB || iterations > MAX_ITERATIONS || parallelism < 1 || parallelism > MAX_PARALLELISM) {
        throw new IllegalArgumentException(
            "Argon2id parameters out of bounds (at most " + MAX_MEMORY_KIB + " KiB, " + MAX_ITERATIONS
                + " passes, 1 to " + MAX_PARALLELISM + " lanes): m=" + memoryKib + ", t=" + iterations + ", p=" + parallelism);
      }
      boolean meetsAMinimum = false;
      for (int[] minimum : OWASP_MINIMUMS) {
        meetsAMinimum |= memoryKib >= minimum[0] && iterations >= minimum[1];
      }
      if (!meetsAMinimum || memoryKib < 8 * parallelism) {
        throw new IllegalArgumentException(
            "Argon2id parameters below OWASP's minimum (for example 19456 KiB and 2 passes): m="
                + memoryKib + ", t=" + iterations + ", p=" + parallelism);
      }
    }

    /** {@code $argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>}, the parameter part of a PHC string. */
    public String encode() {
      return "$argon2id$v=19$m=" + memoryKib + ",t=" + iterations + ",p=" + parallelism;
    }

    /**
     * The parameters in {@code encoded}, exactly as written.
     *
     * @throws IllegalArgumentException if it isn't Argon2id version 19 in the form {@link #encode}
     *     writes, or a value is out of bounds. Never adjusted: that would derive a different key.
     */
    public static Params decode(String encoded) {
      Matcher m = encoded == null ? null : ENCODED.matcher(encoded);
      if (m == null || !m.matches()) {
        throw new IllegalArgumentException("Not Argon2id v19 parameters: " + encoded);
      }
      return new Params(Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)));
    }

    /** Whether these parameters cost less than {@code other}: less memory or fewer passes. */
    public boolean isWeakerThan(Params other) {
      return memoryKib < other.memoryKib || iterations < other.iterations;
    }
  }

  private static final SecureRandom RANDOM = new SecureRandom();

  private final int budgetKib;
  private final Semaphore memory;
  private final ToLongFunction<Params> timer;

  /** A quarter of the maximum heap as the memory budget. */
  public Argon2idKdf() {
    this(Runtime.getRuntime().maxMemory() / 4 / 1024);
  }

  /**
   * @param budgetKib memory all concurrent derivations may use together, in KiB.
   */
  public Argon2idKdf(long budgetKib) {
    this(budgetKib, null);
  }

  /** With {@code timer} measuring one derivation in nanoseconds, for calibration tests; null measures for real. */
  Argon2idKdf(long budgetKib, ToLongFunction<Params> timer) {
    if (budgetKib < Params.DEFAULT.memoryKib()) {
      throw new IllegalArgumentException(
          "The memory budget (" + budgetKib + " KiB) is below one derivation at the default cost ("
              + Params.DEFAULT.memoryKib() + " KiB): give the JVM more heap");
    }
    this.budgetKib = (int) Math.min(budgetKib, Integer.MAX_VALUE);
    this.memory = new Semaphore(this.budgetKib, true);
    this.timer = timer != null ? timer : this::timeOnce;
  }

  /** The memory budget, in KiB. */
  public int budgetKib() {
    return budgetKib;
  }

  /** A new random salt of {@link #SALT_BYTES}. */
  public static byte[] newSalt() {
    byte[] salt = new byte[SALT_BYTES];
    RANDOM.nextBytes(salt);
    return salt;
  }

  /**
   * A 256-bit AES key from {@code password}. The caller's array is not changed; clear it when done.
   *
   * @see #deriveKey
   */
  public SecretKey deriveAesKey(char[] password, byte[] salt, Params params) {
    byte[] key = deriveKey(password, salt, params, 32);
    try {
      return new SecretKeySpec(key, "AES");
    } finally {
      Arrays.fill(key, (byte) 0);
    }
  }

  /**
   * {@code keyBytes} of key material from {@code password}, which is encoded as UTF-8 without
   * normalisation (as RFC 9106 leaves it to the application: normalise first if the same password may
   * arrive in different Unicode forms). Blocks while other derivations hold the memory it needs.
   *
   * @throws IllegalArgumentException if the password isn't valid UTF-16 (a lone surrogate, which a
   *     lenient encoder would turn into "?", so different passwords would give the same key), the
   *     salt is shorter than {@link #SALT_BYTES} or longer than 64 bytes, {@code keyBytes} isn't 16
   *     to 64, or {@code params} needs more memory than the whole budget.
   */
  public byte[] deriveKey(char[] password, byte[] salt, Params params, int keyBytes) {
    if (salt == null || salt.length < SALT_BYTES || salt.length > MAX_SALT_BYTES) {
      throw new IllegalArgumentException("The salt must be " + SALT_BYTES + " to " + MAX_SALT_BYTES + " bytes");
    }
    if (keyBytes < MIN_KEY_BYTES || keyBytes > MAX_KEY_BYTES) {
      throw new IllegalArgumentException("The key must be " + MIN_KEY_BYTES + " to " + MAX_KEY_BYTES + " bytes: " + keyBytes);
    }
    byte[] passwordBytes = utf8(password);
    try {
      return withMemory(params, () -> argon2(passwordBytes, salt, params, keyBytes));
    } finally {
      Arrays.fill(passwordBytes, (byte) 0);
    }
  }

  /**
   * The most memory, doubling from {@link Params#DEFAULT} and within the budget, for which one
   * derivation on this machine takes at most {@code target}; never less than the default. Takes a few
   * seconds: run it once (at startup or when creating a key), not per request.
   *
   * <p>Each candidate is timed three times and judged by the median, after a warm-up derivation:
   * the first derivation in a JVM runs before the JIT compiler has optimised it and takes about
   * 1.6 times as long (measured: 492 ms, then about 300 ms, for 128 MiB on an Apple M1).
   */
  public Params calibrate(Duration target) {
    long targetNanos = target.toNanos();
    Params chosen = Params.DEFAULT;
    timer.applyAsLong(chosen); // warm-up, not judged
    while (chosen.memoryKib() <= budgetKib / 2 && chosen.memoryKib() * 2 <= Params.MAX_MEMORY_KIB) {
      Params next = new Params(chosen.memoryKib() * 2, chosen.iterations(), chosen.parallelism());
      long[] samples = {timer.applyAsLong(next), timer.applyAsLong(next), timer.applyAsLong(next)};
      Arrays.sort(samples);
      if (samples[1] > targetNanos) {
        break;
      }
      chosen = next;
    }
    return chosen;
  }

  /** One real derivation of a fixed input, timed with the monotonic clock. */
  private long timeOnce(Params params) {
    byte[] salt = new byte[SALT_BYTES];
    long start = System.nanoTime();
    deriveKey(new char[] {'c', 'a', 'l', 'i', 'b', 'r', 'a', 't', 'e'}, salt, params, 32);
    return System.nanoTime() - start;
  }

  /** Runs {@code work} holding {@code params.memoryKib()} of the budget. */
  private byte[] withMemory(Params params, java.util.function.Supplier<byte[]> work) {
    int needed = params.memoryKib();
    if (needed > budgetKib) {
      throw new IllegalArgumentException(
          "One derivation needs " + needed + " KiB, more than the whole budget of " + budgetKib + " KiB");
    }
    try {
      memory.acquire(needed);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("Interrupted while waiting for memory to derive a key", e);
    }
    try {
      return work.get();
    } finally {
      memory.release(needed);
    }
  }

  /** Whether {@code kib} of the budget is free right now (for the tests). */
  boolean hasFree(int kib) {
    return memory.availablePermits() >= kib;
  }

  /** Argon2id, version 19, with no secret or associated data. Bouncy Castle clears its memory blocks afterwards. */
  static byte[] argon2(byte[] password, byte[] salt, Params params, int keyBytes) {
    Argon2BytesGenerator generator = new Argon2BytesGenerator();
    generator.init(
        new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withMemoryAsKB(params.memoryKib())
            .withIterations(params.iterations())
            .withParallelism(params.parallelism())
            .withSalt(salt)
            .build());
    byte[] key = new byte[keyBytes];
    generator.generateBytes(password, key);
    return key;
  }

  /** Strict UTF-8: a lone surrogate is an error, not a "?". The encoder's buffer is cleared. */
  private static byte[] utf8(char[] password) {
    if (password == null) {
      throw new IllegalArgumentException("The password must not be null");
    }
    ByteBuffer encoded;
    try {
      encoded =
          StandardCharsets.UTF_8
              .newEncoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT)
              .encode(CharBuffer.wrap(password));
    } catch (CharacterCodingException e) {
      throw new IllegalArgumentException("The password is not valid Unicode text", e);
    }
    byte[] bytes = new byte[encoded.remaining()];
    encoded.get(bytes);
    Arrays.fill(encoded.array(), (byte) 0);
    return bytes;
  }
}

package com.lattice.oidc.security;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.crypto.SecretKey;
import org.junit.Test;

/** Password-based key derivation: the algorithm, the stored parameters, the memory budget, calibration. */
public class Argon2idKdfTest {

  private static final Argon2idKdf.Params DEFAULT = Argon2idKdf.Params.DEFAULT;

  /** Large enough for two derivations at the default cost (64 MiB each). */
  private final Argon2idKdf kdf = new Argon2idKdf(2L * DEFAULT.memoryKib());

  @Test
  public void matchesTheArgon2ReferenceImplementation() {
    // From the reference implementation's test suite (phc-winner-argon2, src/test.c): Argon2id
    // version 19, m = 64 MiB, t = 2, p = 1, password "password", salt "somesalt".
    byte[] key =
        Argon2idKdf.argon2(
            "password".getBytes(StandardCharsets.UTF_8),
            "somesalt".getBytes(StandardCharsets.UTF_8),
            new Argon2idKdf.Params(65_536, 2, 1),
            32);
    assertEquals("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7", HexFormat.of().formatHex(key));
  }

  @Test
  public void theSameInputsGiveTheSameKeyAndAnyChangeGivesAnother() {
    byte[] salt = Argon2idKdf.newSalt();
    byte[] key = kdf.deriveKey("correct horse".toCharArray(), salt, DEFAULT, 32);
    assertArrayEquals(key, kdf.deriveKey("correct horse".toCharArray(), salt, DEFAULT, 32));
    assertFalse(Arrays.equals(key, kdf.deriveKey("correct horsf".toCharArray(), salt, DEFAULT, 32)));
    assertFalse(Arrays.equals(key, kdf.deriveKey("correct horse".toCharArray(), Argon2idKdf.newSalt(), DEFAULT, 32)));
    assertFalse(Arrays.equals(key, kdf.deriveKey("correct horse".toCharArray(), salt, new Argon2idKdf.Params(65_536, 4, 1), 32)));
  }

  @Test
  public void anAesKeyIs256Bits() {
    SecretKey key = kdf.deriveAesKey("pw".toCharArray(), Argon2idKdf.newSalt(), DEFAULT);
    assertEquals("AES", key.getAlgorithm());
    assertEquals(32, key.getEncoded().length);
  }

  @Test
  public void theCallersPasswordIsLeftAlone() {
    char[] password = "secret".toCharArray();
    kdf.deriveKey(password, Argon2idKdf.newSalt(), DEFAULT, 32);
    assertArrayEquals("secret".toCharArray(), password);
  }

  @Test
  public void aLoneSurrogateIsRefusedNotTurnedIntoAQuestionMark() {
    // A lenient encoder would encode both as "a?", giving two passwords the same key.
    char[] lone = {'a', '\uD800'};
    assertThrows(IllegalArgumentException.class, () -> kdf.deriveKey(lone, Argon2idKdf.newSalt(), DEFAULT, 32));
    // A proper pair is fine.
    kdf.deriveKey("a😀".toCharArray(), Argon2idKdf.newSalt(), DEFAULT, 32);
  }

  @Test
  public void shortSaltsAndOddKeyLengthsAreRefused() {
    assertThrows(IllegalArgumentException.class, () -> kdf.deriveKey("pw".toCharArray(), new byte[8], DEFAULT, 32));
    assertThrows(IllegalArgumentException.class, () -> kdf.deriveKey("pw".toCharArray(), null, DEFAULT, 32));
    assertThrows(IllegalArgumentException.class, () -> kdf.deriveKey("pw".toCharArray(), new byte[16], DEFAULT, 8));
    assertThrows(IllegalArgumentException.class, () -> kdf.deriveKey("pw".toCharArray(), new byte[16], DEFAULT, 65));
  }

  @Test
  public void parametersRoundTripThroughTheirStoredForm() {
    assertEquals("$argon2id$v=19$m=65536,t=3,p=1", DEFAULT.encode());
    assertEquals(DEFAULT, Argon2idKdf.Params.decode(DEFAULT.encode()));
    Argon2idKdf.Params other = new Argon2idKdf.Params(131_072, 4, 2);
    assertEquals(other, Argon2idKdf.Params.decode(other.encode()));
  }

  @Test
  public void storedParametersAreRefusedNotAdjusted() {
    for (String bad :
        new String[] {
          null,
          "",
          "$argon2i$v=19$m=65536,t=3,p=1", // another Argon2 type
          "$argon2id$v=16$m=65536,t=3,p=1", // another version
          "$argon2id$m=65536,t=3,p=1", // version missing
          "$argon2id$v=19$m=65536,t=3,p=1$extra",
          "$argon2id$v=19$m=1024,t=3,p=1", // below OWASP's minimum
          "$argon2id$v=19$m=4194304,t=3,p=1", // 4 GiB: over the bound
          "$argon2id$v=19$m=65536,t=99,p=1",
          "$argon2id$v=19$m=65536,t=3,p=0",
          "$argon2id$v=19$m=99999999999,t=3,p=1"
        }) {
      assertThrows(bad, IllegalArgumentException.class, () -> Argon2idKdf.Params.decode(bad));
    }
  }

  @Test
  public void weakerParametersAreDetected() {
    assertTrue(new Argon2idKdf.Params(19_456, 2, 1).isWeakerThan(DEFAULT));
    assertTrue(new Argon2idKdf.Params(131_072, 2, 1).isWeakerThan(DEFAULT)); // more memory, fewer passes
    assertFalse(DEFAULT.isWeakerThan(DEFAULT));
    assertFalse(new Argon2idKdf.Params(131_072, 3, 1).isWeakerThan(DEFAULT));
  }

  @Test
  public void aBudgetBelowOneDerivationIsRefused() {
    assertThrows(IllegalArgumentException.class, () -> new Argon2idKdf(DEFAULT.memoryKib() - 1));
  }

  @Test
  public void parametersLargerThanTheWholeBudgetAreRefusedRatherThanWaitingForever() {
    Argon2idKdf small = new Argon2idKdf(DEFAULT.memoryKib());
    Argon2idKdf.Params big = new Argon2idKdf.Params(DEFAULT.memoryKib() * 2, 3, 1);
    assertThrows(IllegalArgumentException.class, () -> small.deriveKey("pw".toCharArray(), Argon2idKdf.newSalt(), big, 32));
  }

  @Test
  public void derivationsThatWouldExceedTheBudgetWait() throws Exception {
    // Room for one derivation at a time: while one runs, its memory is taken and the next waits.
    Argon2idKdf one = new Argon2idKdf(DEFAULT.memoryKib());
    Argon2idKdf.Params slow = new Argon2idKdf.Params(DEFAULT.memoryKib(), 10, 1);
    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      CountDownLatch started = new CountDownLatch(1);
      Future<byte[]> first =
          pool.submit(
              () -> {
                started.countDown();
                return one.deriveKey("a".toCharArray(), Argon2idKdf.newSalt(), slow, 32);
              });
      started.await();
      // Wait until the first derivation holds the budget.
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
      while (one.hasFree(DEFAULT.memoryKib()) && System.nanoTime() < deadline) {
        Thread.onSpinWait();
      }
      assertFalse("the first derivation holds the budget", one.hasFree(1));
      Future<byte[]> second = pool.submit(() -> one.deriveKey("b".toCharArray(), Argon2idKdf.newSalt(), DEFAULT, 32));
      assertEquals(32, first.get(30, TimeUnit.SECONDS).length);
      assertEquals(32, second.get(30, TimeUnit.SECONDS).length);
      assertTrue("the budget is returned", one.hasFree(DEFAULT.memoryKib()));
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  public void calibrationPicksTheMostMemoryWithinTheTargetTime() {
    // A fake machine on which a derivation takes 5 microseconds per KiB: 64 MiB takes 328 ms,
    // 128 MiB 655 ms. With a 500 ms target, 64 MiB is the most that fits.
    Argon2idKdf fake = new Argon2idKdf(1_048_576, params -> params.memoryKib() * 5_000L);
    assertEquals(DEFAULT, fake.calibrate(Duration.ofMillis(500)));
    // With a second, 128 MiB fits (655 ms) but 256 MiB (1.3 s) doesn't.
    assertEquals(new Argon2idKdf.Params(131_072, 3, 1), fake.calibrate(Duration.ofSeconds(1)));
  }

  @Test
  public void calibrationNeverGoesBelowTheDefaultOrBeyondTheBudget() {
    Argon2idKdf slowMachine = new Argon2idKdf(1_048_576, params -> Long.MAX_VALUE);
    assertEquals(DEFAULT, slowMachine.calibrate(Duration.ofMillis(1)));
    // Instant derivations: limited by the 256 MiB budget, not by time.
    Argon2idKdf fastMachine = new Argon2idKdf(262_144, params -> 0L);
    assertEquals(new Argon2idKdf.Params(262_144, 3, 1), fastMachine.calibrate(Duration.ofSeconds(1)));
  }

  @Test
  public void calibrationRunsOnThisMachine() {
    // Real timings: a 128 MiB budget allows one doubling, so this costs about a second.
    Argon2idKdf.Params chosen = new Argon2idKdf(131_072).calibrate(Duration.ofMillis(500));
    assertTrue(chosen.memoryKib() == 65_536 || chosen.memoryKib() == 131_072);
    assertEquals(DEFAULT.iterations(), chosen.iterations());
  }

  @Test
  public void calibrationJudgesTheMedianNotAnOutlier() {
    // Every third timing of 128 MiB is a 10-second outlier (a GC pause, say): the median still fits.
    int[] calls = {0};
    Argon2idKdf noisy =
        new Argon2idKdf(
            262_144,
            params -> {
              if (params.memoryKib() == 131_072 && calls[0]++ % 3 == 0) return 10_000_000_000L;
              return params.memoryKib() == 131_072 ? 400_000_000L : 900_000_000L;
            });
    assertEquals(new Argon2idKdf.Params(131_072, 3, 1), noisy.calibrate(Duration.ofMillis(500)));
  }
}

package com.lattice.oidc.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
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
    PasswordHasher.configure(PasswordHasher.Cost.DEFAULT);
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
                          return com.password4j.Password.check("secret", hash)
                              .with(com.password4j.Argon2Function.getInstanceFromHash(hash));
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

  // ---------------------------------------------------------------- compatibility

  private static final List<String> PASSWORDS =
      List.of("a", "secret", "correct horse battery staple", "pässwörd", "\uD83D\uDD10 pass \u00e9\u4e2d", "x".repeat(200));

  /** password4j (the previous implementation) is the independent oracle: what it wrote must verify here. */
  @Test
  public void hashesFromPassword4jStillVerify() {
    for (String password : PASSWORDS) {
      String old = com.password4j.Password.hash(password).addRandomSalt().withArgon2().getResult();
      assertTrue(password, PasswordHasher.check(password, old));
      assertFalse(password, PasswordHasher.check(password + "!", old));
    }
  }

  /**
   * And the reverse: the hashes written here are valid Argon2id, which password4j verifies when it is
   * told to take the parameters from the hash. Its plain {@code check(...).withArgon2()} does not: it
   * uses its own defaults (15 MiB) and so cannot verify a hash made with another memory size.
   */
  @Test
  public void hashesFromHereVerifyInPassword4j() {
    for (String password : PASSWORDS) {
      String hash = PasswordHasher.hash(password);
      com.password4j.Argon2Function fromHash = com.password4j.Argon2Function.getInstanceFromHash(hash);
      assertTrue(password, com.password4j.Password.check(password, hash).with(fromHash));
      assertFalse(password, com.password4j.Password.check(password + "!", hash).with(fromHash));
    }
  }

  /** The caveat of the test above, kept as a test so that it is not forgotten when rolling back. */
  @Test
  public void password4jsPlainCheckDoesNotReadTheMemorySizeFromTheHash() {
    String hash = PasswordHasher.hash("secret");
    assertFalse(
        "the old code's check(...).withArgon2() uses 15 MiB whatever the hash says",
        com.password4j.Password.check("secret", hash).withArgon2());
  }

  /** A hash written by the old implementation, kept as text: it must keep verifying even without that library. */
  @Test
  public void aStoredHashFromTheOldImplementationVerifies() {
    String stored =
        "$argon2id$v=19$m=15360,t=2,p=1$hlPPRmUun4z4JgB96/UhRVpkcDRWLwhFlnT4Mr74MGrHtM7aBrotXbgzdy11kikRRcJJKNjXIGBvhMsdJrcFOw$KQ1NFErzjVNjikS8FHXMHnTTCGvgJ4wAm+/ZJmD1FOc";
    assertTrue(PasswordHasher.check("p\u00e4ssw\u00f6rd", stored));
    assertFalse(PasswordHasher.check("password", stored));
  }

  /** The parameters come from the stored string, so hashes with other costs, types and versions verify. */
  @Test
  public void hashesWithOtherParametersVerify() {
    // memory 4096 KiB, 3 passes, 2 lanes: Argon2id version 19
    String id = com.password4j.Password.hash("secret").addRandomSalt()
        .with(com.password4j.Argon2Function.getInstance(4096, 3, 2, 32, com.password4j.types.Argon2.ID)).getResult();
    assertTrue(id, id.startsWith("$argon2id$v=19$m=4096,t=3,p=2$"));
    assertTrue(PasswordHasher.check("secret", id));
    assertFalse(PasswordHasher.check("other", id));

    String i = com.password4j.Password.hash("secret").addRandomSalt()
        .with(com.password4j.Argon2Function.getInstance(4096, 2, 1, 32, com.password4j.types.Argon2.I)).getResult();
    assertTrue(i, i.startsWith("$argon2i$"));
    assertTrue(PasswordHasher.check("secret", i));
  }

  @Test
  public void newHashesUseTheCurrentParametersAndARandomSalt() {
    String first = PasswordHasher.hash("secret");
    assertTrue(first, first.startsWith("$argon2id$v=19$m=19456,t=2,p=1$"));
    assertNotEquals("a new salt each time", first, PasswordHasher.hash("secret"));
  }

  /** Hashes weaker than a new one are replaced at sign-in; stronger or equal ones are left alone. */
  @Test
  public void aHashWeakerThanTheCurrentOneNeedsRehashing() {
    String salt = "c29tZXNhbHRzb21lc2FsdA";
    String hash = "KQ1NFErzjVNjikS8FHXMHnTTCGvgJ4wAm+/ZJmD1FOc";
    // Made before the cost was raised: 15 MiB.
    assertTrue(PasswordHasher.needsRehash("$argon2id$v=19$m=15360,t=2,p=1$" + salt + "$" + hash));
    assertTrue("fewer passes", PasswordHasher.needsRehash("$argon2id$v=19$m=19456,t=1,p=1$" + salt + "$" + hash));
    assertTrue("another type", PasswordHasher.needsRehash("$argon2i$v=19$m=19456,t=2,p=1$" + salt + "$" + hash));
    assertTrue("another version", PasswordHasher.needsRehash("$argon2id$v=16$m=19456,t=2,p=1$" + salt + "$" + hash));
    assertTrue("a shorter output", PasswordHasher.needsRehash("$argon2id$v=19$m=19456,t=2,p=1$" + salt + "$AAAAAAAAAAAAAAAAAAAAAA"));

    assertFalse("a new hash", PasswordHasher.needsRehash(PasswordHasher.hash("secret")));
    assertFalse("more memory", PasswordHasher.needsRehash("$argon2id$v=19$m=65536,t=2,p=1$" + salt + "$" + hash));
    assertFalse("more passes", PasswordHasher.needsRehash("$argon2id$v=19$m=19456,t=3,p=1$" + salt + "$" + hash));
    assertFalse("malformed: nothing to upgrade", PasswordHasher.needsRehash("not a hash"));
    assertFalse(PasswordHasher.needsRehash(null));
  }

  /** A corrupt or hostile stored string is a wrong password: no exception, and no huge allocation. */
  @Test
  public void malformedOrHostileStoredHashesNeverMatch() {
    String salt = "c29tZXNhbHRzb21lc2FsdA";
    String hash = "KQ1NFErzjVNjikS8FHXMHnTTCGvgJ4wAm+/ZJmD1FOc";
    for (String stored :
        java.util.Arrays.asList(
            null,
            "",
            "not a hash",
            "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
            "$argon2id$v=19$m=15360,t=2,p=1$" + salt,
            "$argon2id$v=19$m=15360,t=2,p=1$AAAA$" + hash,
            "$argon2id$v=19$m=999999999,t=2,p=1$" + salt + "$" + hash,
            "$argon2id$v=19$m=15360,t=1000000,p=1$" + salt + "$" + hash,
            "$argon2id$v=19$m=15360,t=2,p=0$" + salt + "$" + hash,
            "$argon2id$v=19$m=15360,t=2,p=9999$" + salt + "$" + hash,
            "$argon2id$v=99$m=15360,t=2,p=1$" + salt + "$" + hash,
            "$argon2id$v=19$m=15360,t=2,p=1$" + salt + "$AA")) {
      assertFalse(String.valueOf(stored), PasswordHasher.check("secret", stored));
    }
    assertFalse("no password", PasswordHasher.check(null, PasswordHasher.hash("secret")));
  }

  @Test(expected = IllegalArgumentException.class)
  public void theLimitIsAtLeastOne() {
    PasswordHasher.configure(0);
  }

  // ---------------------------------------------------------------- configured cost

  /** Any of OWASP's equally strong minimums, or more, is accepted. */
  @Test
  public void costsAtOrAboveAnOwaspMinimumAreAccepted() {
    for (int[] c : new int[][] {{47_104, 1}, {19_456, 2}, {12_288, 3}, {9_216, 4}, {7_168, 5}, {65_536, 3}, {19_456, 4}}) {
      new PasswordHasher.Cost(c[0], c[1], 1);
    }
    new PasswordHasher.Cost(19_456, 2, 4);
  }

  /** A typo must not quietly make every new hash weak, or unverifiable: the server refuses to start. */
  @Test
  public void costsBelowTheMinimumOrBeyondTheBoundsAreRefused() {
    for (int[] c :
        new int[][] {
          {19_455, 2, 1}, // just under 19 MiB with 2 passes
          {12_288, 2, 1}, // 12 MiB needs 3 passes
          {47_103, 1, 1}, // 1 pass needs 46 MiB
          {1_024, 20, 1}, // many passes can't make up for too little memory
          {19_456, 2, 0},
          {19_456, 2, 33},
          {262_145, 2, 1}, // more memory than a stored hash may ask for
          {19_456, 21, 1}
        }) {
      try {
        new PasswordHasher.Cost(c[0], c[1], c[2]);
        throw new AssertionError("accepted m=" + c[0] + ", t=" + c[1] + ", p=" + c[2]);
      } catch (IllegalArgumentException expected) {
        // refused
      }
    }
  }

  @Test
  public void newHashesUseTheConfiguredCostAndOlderOnesNeedRehashing() {
    String atDefault = PasswordHasher.hash("secret");
    PasswordHasher.configure(new PasswordHasher.Cost(24_576, 2, 1));
    String raised = PasswordHasher.hash("secret");
    assertTrue(raised, raised.startsWith("$argon2id$v=19$m=24576,t=2,p=1$"));
    assertTrue(PasswordHasher.check("secret", raised));
    assertFalse(PasswordHasher.needsRehash(raised));
    assertTrue("less memory than now configured", PasswordHasher.needsRehash(atDefault));
    assertTrue("and it still verifies", PasswordHasher.check("secret", atDefault));
  }
}

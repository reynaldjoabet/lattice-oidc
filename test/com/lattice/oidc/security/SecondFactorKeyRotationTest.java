package com.lattice.oidc.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.lattice.oidc.stores.InMemorySecondFactorStore;
import com.lattice.oidc.stores.SecondFactorStore;
import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** Rotating the key that encrypts authenticator secrets and hashes recovery codes. */
public class SecondFactorKeyRotationTest {

  private static Config config(String key, Object previous) {
    return ConfigFactory.parseMap(
            Map.of(
                "lattice.second-factor.encryption-key", key,
                "lattice.second-factor.previous-encryption-keys", previous,
                "lattice.second-factor.acr", "mfa",
                "lattice.ui.brand-name", "Lattice"))
        .resolve();
  }

  private static SecretCipher cipher(String key, Object previous) {
    return new SecretCipher(config(key, previous));
  }

  private static SecondFactors secondFactors(SecondFactorStore store, String key, Object previous) {
    return new SecondFactors(store, cipher(key, previous), config(key, previous));
  }

  private static String currentCode(String secret) {
    return TotpCodes.at(secret, Totp.step(Instant.now()));
  }

  @Test
  public void valuesCarryTheirKeyIdAndOldKeysStillRead() {
    SecretCipher old = cipher("old-key", List.of());
    SecretCipher rotated = cipher("new-key", List.of("old-key"));
    String sealed = old.encrypt("JBSWY3DPEHPK3PXP");

    assertTrue(sealed.startsWith(old.currentKeyId() + ":"));
    assertEquals("JBSWY3DPEHPK3PXP", rotated.decrypt(sealed));
    assertFalse(rotated.isCurrent(sealed));
    assertTrue(rotated.isCurrent(rotated.encrypt("x")));
    assertEquals(1, rotated.previousKeyCount());
    assertTrue(rotated.storedHashes("ABCDE12345").contains(old.hash("ABCDE12345")));
  }

  @Test
  public void valuesFromBeforeKeyIdsAreTriedWithEveryKey() {
    SecretCipher old = cipher("old-key", List.of());
    String legacy = old.encrypt("JBSWY3DPEHPK3PXP").substring(old.currentKeyId().length() + 1);
    assertEquals("JBSWY3DPEHPK3PXP", cipher("new-key", "old-key").decrypt(legacy));
  }

  @Test
  public void aRemovedKeyIsNamedInTheError() {
    SecretCipher old = cipher("old-key", List.of());
    String sealed = old.encrypt("JBSWY3DPEHPK3PXP");
    IllegalStateException error = assertThrows(IllegalStateException.class, () -> cipher("new-key", List.of()).decrypt(sealed));
    assertTrue(error.getMessage(), error.getMessage().contains(old.currentKeyId()));
  }

  @Test
  public void aSecretMovesToTheNewKeyWhenItIsUsed() {
    InMemorySecondFactorStore store = new InMemorySecondFactorStore();
    String secret = Totp.newSecret();
    assertTrue(secondFactors(store, "old-key", List.of()).finishEnrollment("alice", secret, currentCode(secret)));
    // The enrolment used the current step; the next sign-in has to wait for a later one.
    store.saveTotp(new SecondFactorStore.Totp("alice", store.totp("alice").orElseThrow().encryptedSecret(), Instant.now(), 0));

    SecondFactors rotated = secondFactors(store, "new-key", List.of("old-key"));
    assertEquals(1, rotated.status().secretsUnderPreviousKeys());
    assertTrue(rotated.verifyCode("alice", currentCode(secret)));
    assertEquals(0, rotated.status().secretsUnderPreviousKeys());
    assertTrue(store.totp("alice").orElseThrow().encryptedSecret().startsWith(rotated.status().keyId() + ":"));
    assertTrue("the used step is kept", store.totp("alice").orElseThrow().lastUsedStep() > 0);
  }

  @Test
  public void reencryptAllMovesEverySecret() {
    InMemorySecondFactorStore store = new InMemorySecondFactorStore();
    SecretCipher old = cipher("old-key", List.of());
    for (int index = 0; index < 1_200; index++) {
      store.saveTotp(new SecondFactorStore.Totp("user-" + index, old.encrypt(Totp.newSecret()), Instant.now(), 0));
    }
    SecondFactors rotated = secondFactors(store, "new-key", "old-key");
    assertEquals(1_200, rotated.reencryptAll());
    assertEquals(0, rotated.status().secretsUnderPreviousKeys());
    assertEquals(0, rotated.reencryptAll());
  }

  @Test
  public void recoveryCodesFromThePreviousKeyStillWorkUntilReplaced() {
    InMemorySecondFactorStore store = new InMemorySecondFactorStore();
    List<String> codes = secondFactors(store, "old-key", List.of()).newRecoveryCodes("alice");

    SecondFactors rotated = secondFactors(store, "new-key", List.of("old-key"));
    assertEquals(1, rotated.status().recoveryCodesUnderPreviousKeys());
    assertTrue(rotated.useRecoveryCode("alice", codes.get(0)));
    assertFalse("used once", rotated.useRecoveryCode("alice", codes.get(0)));

    rotated.newRecoveryCodes("alice");
    assertEquals(0, rotated.status().recoveryCodesUnderPreviousKeys());
  }
}

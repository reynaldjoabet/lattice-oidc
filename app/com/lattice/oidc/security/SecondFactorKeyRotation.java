package com.lattice.oidc.security;

import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * After a key rotation ({@code lattice.second-factor.previous-encryption-keys} set), re-encrypts the
 * authenticator secrets still under a previous key, in the background at startup. Secrets are also
 * re-encrypted when they're used, so this only finishes the job for accounts that don't sign in.
 */
@Singleton
public final class SecondFactorKeyRotation {

  private static final Logger LOG = LoggerFactory.getLogger(SecondFactorKeyRotation.class);

  @Inject
  public SecondFactorKeyRotation(SecretCipher cipher, SecondFactors secondFactors) {
    if (cipher.previousKeyCount() == 0) {
      return;
    }
    Thread.ofVirtual()
        .name("second-factor-key-rotation")
        .start(
            () -> {
              try {
                int reencrypted = secondFactors.reencryptAll();
                LOG.info("Re-encrypted {} authenticator secrets under key {}", reencrypted, cipher.currentKeyId());
              } catch (RuntimeException e) {
                LOG.warn("Re-encrypting authenticator secrets stopped: {}", e.getMessage(), e);
              }
            });
  }
}

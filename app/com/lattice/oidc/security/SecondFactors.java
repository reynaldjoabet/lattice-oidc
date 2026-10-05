package com.lattice.oidc.security;

import com.lattice.oidc.common.QrCodes;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.SecondFactorStore;
import com.typesafe.config.Config;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.OptionalLong;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authenticator apps (TOTP) and recovery codes. Once an account has an authenticator app, password
 * sign-in also asks for a code from it; a recovery code can be used instead, once. Signing in this
 * way asserts the ACR {@code lattice.second-factor.acr}.
 */
@Singleton
public final class SecondFactors {

  /**
   * For the operator console: accounts with an authenticator app, the current key id, and what is
   * still under a previous key (a previous key can be removed once both are zero).
   */
  public record Status(long accountsWithApp, String keyId, int previousKeys, long secretsUnderPreviousKeys, long recoveryCodesUnderPreviousKeys) {}

  /** A new authenticator app being set up: its secret, the otpauth URI, and that URI as a QR code. */
  public record Enrollment(String secret, String uri, String qrSvg) {}

  private static final Logger LOG = LoggerFactory.getLogger(SecondFactors.class);
  static final int RECOVERY_CODES = 10;
  private static final String CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  private static final SecureRandom RANDOM = new SecureRandom();

  private final SecondFactorStore store;
  private final SecretCipher cipher;
  private final String issuer;
  private final String acr;

  @Inject
  public SecondFactors(SecondFactorStore store, SecretCipher cipher, Config config) {
    this.store = store;
    this.cipher = cipher;
    this.issuer = config.getString("lattice.ui.brand-name");
    this.acr = config.getString("lattice.second-factor.acr");
  }

  public String acr() {
    return acr;
  }

  public boolean enrolled(String subject) {
    return store.totp(subject).isPresent();
  }

  /** Starts setting up an authenticator app; nothing is stored until a code confirms it. */
  public Enrollment startEnrollment(User user) {
    return enrollment(user, Totp.newSecret());
  }

  /** The enrollment for an existing pending secret (to show its QR code again). */
  public Enrollment enrollment(User user, String secret) {
    String account = user.email().orElse(user.loginId() != null ? user.loginId() : user.getSubject());
    String uri = Totp.uri(issuer, account, secret);
    return new Enrollment(secret, uri, QrCodes.svg(uri, "QR code for your authenticator app"));
  }

  /** Saves the app if {@code code} is a current code for {@code secret}. */
  public boolean finishEnrollment(String subject, String secret, String code) {
    OptionalLong step = Totp.verify(secret, code, Instant.now());
    if (step.isEmpty()) {
      return false;
    }
    store.saveTotp(new SecondFactorStore.Totp(subject, cipher.encrypt(secret), Instant.now(), step.getAsLong()));
    return true;
  }

  /** Whether {@code code} is a current, not yet used code from the account's authenticator app. */
  public boolean verifyCode(String subject, String code) {
    return store
        .totp(subject)
        .map(
            totp -> {
              String secret = cipher.decrypt(totp.encryptedSecret());
              OptionalLong step = Totp.verify(secret, code, Instant.now());
              if (step.isEmpty() || !store.useTotpStep(subject, step.getAsLong())) {
                return false;
              }
              reencrypt(totp, secret);
              return true;
            })
        .orElse(false);
  }

  /** Uses up a recovery code; false if it isn't one of the account's unused codes. */
  public boolean useRecoveryCode(String subject, String code) {
    if (code == null || code.isBlank()) {
      return false;
    }
    // Codes made under a previous key (or before key ids) are stored in another form.
    for (String hash : cipher.storedHashes(normalize(code))) {
      if (store.useRecoveryCode(subject, hash)) {
        return true;
      }
    }
    return false;
  }

  /** New recovery codes, replacing any old ones. Shown once; only their hashes are stored. */
  public List<String> newRecoveryCodes(String subject) {
    List<String> codes = new ArrayList<>();
    List<String> hashes = new ArrayList<>();
    for (int i = 0; i < RECOVERY_CODES; i++) {
      StringBuilder code = new StringBuilder();
      for (int character = 0; character < 10; character++) {
        if (character == 5) {
          code.append('-');
        }
        code.append(CODE_ALPHABET.charAt(RANDOM.nextInt(CODE_ALPHABET.length())));
      }
      codes.add(code.toString());
      hashes.add(cipher.hash(normalize(code.toString())));
    }
    store.replaceRecoveryCodes(subject, hashes);
    return codes;
  }

  public int remainingRecoveryCodes(String subject) {
    return store.remainingRecoveryCodes(subject);
  }

  public Status status() {
    String keyId = cipher.currentKeyId();
    return new Status(
        store.accountsWithTotp(),
        keyId,
        cipher.previousKeyCount(),
        store.totpsNotUnderKey(keyId),
        store.accountsWithRecoveryCodesNotUnderKey(keyId));
  }

  /**
   * Re-encrypts every authenticator secret that isn't under the current key; returns how many. Safe
   * to run on several servers at once. A secret under a key that isn't configured is logged and left.
   */
  public int reencryptAll() {
    int reencrypted = 0;
    String after = null;
    while (true) {
      List<SecondFactorStore.Totp> page = store.totps(after, 500);
      for (SecondFactorStore.Totp totp : page) {
        if (cipher.isCurrent(totp.encryptedSecret())) {
          continue;
        }
        try {
          if (reencrypt(totp, cipher.decrypt(totp.encryptedSecret()))) {
            reencrypted++;
          }
        } catch (IllegalStateException e) {
          LOG.warn("Authenticator secret of {} not re-encrypted: {}", totp.subject(), e.getMessage());
        }
      }
      if (page.size() < 500) {
        return reencrypted;
      }
      after = page.get(page.size() - 1).subject();
    }
  }

  /** Stores {@code secret} under the current key, if {@code totp} is under an older one. */
  private boolean reencrypt(SecondFactorStore.Totp totp, String secret) {
    return !cipher.isCurrent(totp.encryptedSecret())
        && store.replaceTotpSecret(totp.subject(), totp.encryptedSecret(), cipher.encrypt(secret));
  }

  /** Removes the authenticator app and the recovery codes. */
  public void remove(String subject) {
    store.deleteTotp(subject);
    store.deleteRecoveryCodes(subject);
  }

  private static String normalize(String code) {
    return code.replaceAll("[\\s-]", "").toUpperCase(Locale.ROOT);
  }
}

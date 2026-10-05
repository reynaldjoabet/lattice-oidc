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

/**
 * Authenticator apps (TOTP) and recovery codes. Once an account has an authenticator app, password
 * sign-in also asks for a code from it; a recovery code can be used instead, once. Signing in this
 * way asserts the ACR {@code lattice.second-factor.acr}.
 */
@Singleton
public final class SecondFactors {

  /** A new authenticator app being set up: its secret, the otpauth URI, and that URI as a QR code. */
  public record Enrollment(String secret, String uri, String qrSvg) {}

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
              OptionalLong step = Totp.verify(cipher.decrypt(totp.encryptedSecret()), code, Instant.now());
              return step.isPresent() && store.useTotpStep(subject, step.getAsLong());
            })
        .orElse(false);
  }

  /** Uses up a recovery code; false if it isn't one of the account's unused codes. */
  public boolean useRecoveryCode(String subject, String code) {
    if (code == null || code.isBlank()) {
      return false;
    }
    return store.useRecoveryCode(subject, cipher.hash(normalize(code)));
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

  /** Removes the authenticator app and the recovery codes. */
  public void remove(String subject) {
    store.deleteTotp(subject);
    store.deleteRecoveryCodes(subject);
  }

  private static String normalize(String code) {
    return code.replaceAll("[\\s-]", "").toUpperCase(Locale.ROOT);
  }
}

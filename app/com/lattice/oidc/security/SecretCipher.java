package com.lattice.oidc.security;

import com.typesafe.config.Config;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;
import javax.inject.Singleton;

/**
 * Encrypts secrets the server must read back (authenticator-app secrets) with AES-256-GCM, and
 * computes keyed hashes of values it only compares (recovery codes). The key comes from {@code
 * lattice.second-factor.encryption-key}, or else the application secret. Changing it makes stored
 * authenticator secrets unreadable, so users would set up their app again.
 */
@Singleton
public final class SecretCipher {

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final int NONCE_BYTES = 12;

  private final byte[] encryptionKey;
  private final byte[] hashKey;

  @Inject
  public SecretCipher(Config config) {
    String configured = config.getString("lattice.second-factor.encryption-key");
    String secret =
        configured.isBlank() && config.hasPath("play.http.secret.key") ? config.getString("play.http.secret.key") : configured;
    this.encryptionKey = derive(secret, "lattice second-factor encryption");
    this.hashKey = derive(secret, "lattice second-factor hashing");
  }

  private static byte[] derive(String secret, String purpose) {
    try {
      return MessageDigest.getInstance("SHA-256").digest((purpose + "|" + secret).getBytes(StandardCharsets.UTF_8));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Base64 of nonce and ciphertext. */
  public String encrypt(String plaintext) {
    try {
      byte[] nonce = new byte[NONCE_BYTES];
      RANDOM.nextBytes(nonce);
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"), new GCMParameterSpec(128, nonce));
      byte[] sealed = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(ByteBuffer.allocate(nonce.length + sealed.length).put(nonce).put(sealed).array());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  public String decrypt(String encrypted) {
    try {
      byte[] all = Base64.getDecoder().decode(encrypted);
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(
          Cipher.DECRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"), new GCMParameterSpec(128, all, 0, NONCE_BYTES));
      return new String(cipher.doFinal(all, NONCE_BYTES, all.length - NONCE_BYTES), StandardCharsets.UTF_8);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("A stored secret could not be decrypted (was the key changed?)", e);
    }
  }

  /** A keyed hash (HMAC-SHA256, base64url) for values that are only compared. */
  public String hash(String value) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(hashKey, "HmacSHA256"));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }
}

package com.lattice.oidc.security;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigValueType;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/**
 * Encrypts secrets the server must read back (authenticator-app secrets) with AES-256-GCM, and
 * computes keyed hashes of values it only compares (recovery codes).
 *
 * <p>The key comes from {@code lattice.second-factor.encryption-key}, or else the application
 * secret. Every value is stored as {@code <key id>:<value>}, so the key can be rotated: set the new
 * key and move the old one to {@code previous-encryption-keys}. Values under a previous key are still
 * read, and {@link SecondFactors} re-encrypts secrets under the new key. Recovery codes can't be
 * re-hashed (only their hashes are kept), so a previous key stays listed until those accounts have
 * new codes; the operator console shows how many are left. Values from before key ids (no prefix)
 * are tried with every key.
 */
@Singleton
public final class SecretCipher {

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final int NONCE_BYTES = 12;

  /** One key: an id (not secret) and the encryption and hashing keys derived from it. */
  private record Key(String id, byte[] encryption, byte[] hashing) {}

  private final Key current;
  /** The current key first, then the previous ones. */
  private final List<Key> keys;

  @Inject
  public SecretCipher(Config config) {
    String configured = config.getString("lattice.second-factor.encryption-key");
    String secret =
        configured.isBlank() && config.hasPath("play.http.secret.key") ? config.getString("play.http.secret.key") : configured;
    this.current = key(secret);
    List<Key> all = new ArrayList<>(List.of(current));
    for (String previous : previousKeys(config)) {
      Key key = key(previous);
      if (all.stream().noneMatch(known -> known.id().equals(key.id()))) {
        all.add(key);
      }
    }
    this.keys = List.copyOf(all);
  }

  /** {@code previous-encryption-keys}: a list, or one comma-separated string (from the environment). */
  private static List<String> previousKeys(Config config) {
    String path = "lattice.second-factor.previous-encryption-keys";
    if (!config.hasPath(path)) {
      return List.of();
    }
    List<String> values =
        config.getValue(path).valueType() == ConfigValueType.LIST
            ? config.getStringList(path)
            : Arrays.asList(config.getString(path).split(","));
    return values.stream().map(String::trim).filter(value -> !value.isEmpty()).toList();
  }

  private static Key key(String secret) {
    // The id is a hash of the secret, so it can be shown in the console and stored with each value.
    String id = HexFormat.of().formatHex(derive(secret, "lattice second-factor key id"), 0, 6);
    return new Key(id, derive(secret, "lattice second-factor encryption"), derive(secret, "lattice second-factor hashing"));
  }

  private static byte[] derive(String secret, String purpose) {
    try {
      return MessageDigest.getInstance("SHA-256").digest((purpose + "|" + secret).getBytes(StandardCharsets.UTF_8));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  /** The id of the key new values are written with. */
  public String currentKeyId() {
    return current.id();
  }

  /** How many previous keys are still accepted. */
  public int previousKeyCount() {
    return keys.size() - 1;
  }

  /** {@code <key id>:} base64 of nonce and ciphertext. */
  public String encrypt(String plaintext) {
    try {
      byte[] nonce = new byte[NONCE_BYTES];
      RANDOM.nextBytes(nonce);
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(current.encryption(), "AES"), new GCMParameterSpec(128, nonce));
      byte[] sealed = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
      byte[] all = ByteBuffer.allocate(nonce.length + sealed.length).put(nonce).put(sealed).array();
      return current.id() + ":" + Base64.getEncoder().encodeToString(all);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  public String decrypt(String encrypted) {
    int colon = encrypted.indexOf(':');
    if (colon < 0) {
      // From before key ids: try each key (GCM rejects the wrong one).
      for (Key key : keys) {
        try {
          return decrypt(key, encrypted);
        } catch (AEADBadTagException wrongKey) {
          // Try the next key.
        } catch (GeneralSecurityException e) {
          throw new IllegalStateException(e);
        }
      }
      throw new IllegalStateException("A stored secret could not be decrypted with any configured key");
    }
    String id = encrypted.substring(0, colon);
    Key key =
        keys.stream()
            .filter(candidate -> candidate.id().equals(id))
            .findFirst()
            .orElseThrow(
                () ->
                    new IllegalStateException(
                        "A stored secret is encrypted with key " + id + ", which isn't configured (add it to previous-encryption-keys)"));
    try {
      return decrypt(key, encrypted.substring(colon + 1));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("A stored secret could not be decrypted with key " + id, e);
    }
  }

  private static String decrypt(Key key, String base64) throws GeneralSecurityException {
    byte[] all = Base64.getDecoder().decode(base64);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.encryption(), "AES"), new GCMParameterSpec(128, all, 0, NONCE_BYTES));
    return new String(cipher.doFinal(all, NONCE_BYTES, all.length - NONCE_BYTES), StandardCharsets.UTF_8);
  }

  /** Whether {@code encrypted} is under the current key (otherwise it should be re-encrypted). */
  public boolean isCurrent(String encrypted) {
    return encrypted.startsWith(current.id() + ":");
  }

  /** A keyed hash (HMAC-SHA256, base64url) with the current key, for values that are only compared. */
  public String hash(String value) {
    return current.id() + ":" + hmac(current, value);
  }

  /** Every form {@code value} may have been stored in: hashed with each key, with and without its id. */
  public List<String> storedHashes(String value) {
    List<String> hashes = new ArrayList<>();
    for (Key key : keys) {
      String hmac = hmac(key, value);
      hashes.add(key.id() + ":" + hmac);
      hashes.add(hmac);
    }
    return hashes;
  }

  private static String hmac(Key key, String value) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key.hashing(), "HmacSHA256"));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }
}

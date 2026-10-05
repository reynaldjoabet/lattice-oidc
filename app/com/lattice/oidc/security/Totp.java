package com.lattice.oidc.security;

import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.OptionalLong;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Time-based one-time passwords (RFC 6238), as authenticator apps generate them: HMAC-SHA1 over a
 * 30-second time step, 6 digits. A code from the previous or next step is also accepted, for clock
 * drift between phone and server.
 */
public final class Totp {

  static final int DIGITS = 6;
  static final long PERIOD_SECONDS = 30;
  private static final int SECRET_BYTES = 20;
  private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  private static final SecureRandom RANDOM = new SecureRandom();

  private Totp() {}

  /** A new random secret, base32 as authenticator apps expect it. */
  public static String newSecret() {
    byte[] bytes = new byte[SECRET_BYTES];
    RANDOM.nextBytes(bytes);
    return base32(bytes);
  }

  public static long step(Instant at) {
    return at.getEpochSecond() / PERIOD_SECONDS;
  }

  /** The code for a time step (RFC 4226 dynamic truncation). */
  static String code(String secret, long step) {
    try {
      Mac mac = Mac.getInstance("HmacSHA1");
      mac.init(new SecretKeySpec(unbase32(secret), "HmacSHA1"));
      byte[] hash = mac.doFinal(ByteBuffer.allocate(8).putLong(step).array());
      int offset = hash[hash.length - 1] & 0x0f;
      int binary =
          ((hash[offset] & 0x7f) << 24)
              | ((hash[offset + 1] & 0xff) << 16)
              | ((hash[offset + 2] & 0xff) << 8)
              | (hash[offset + 3] & 0xff);
      return String.format("%0" + DIGITS + "d", binary % 1_000_000);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * The time step the code belongs to, if it matches the previous, current or next step. Callers
   * must still refuse a step that was already used (replay).
   */
  public static OptionalLong verify(String secret, String code, Instant now) {
    String normalized = code == null ? "" : code.replaceAll("\\s", "");
    if (!normalized.matches("\\d{" + DIGITS + "}")) {
      return OptionalLong.empty();
    }
    long current = step(now);
    for (long step = current - 1; step <= current + 1; step++) {
      byte[] expected = code(secret, step).getBytes(StandardCharsets.US_ASCII);
      if (MessageDigest.isEqual(expected, normalized.getBytes(StandardCharsets.US_ASCII))) {
        return OptionalLong.of(step);
      }
    }
    return OptionalLong.empty();
  }

  /** The {@code otpauth://} URI an authenticator app scans from the QR code. */
  public static String uri(String issuer, String account, String secret) {
    String label = encode(issuer) + ":" + encode(account);
    return "otpauth://totp/" + label + "?secret=" + secret + "&issuer=" + encode(issuer)
        + "&algorithm=SHA1&digits=" + DIGITS + "&period=" + PERIOD_SECONDS;
  }

  private static String encode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
  }

  static String base32(byte[] bytes) {
    StringBuilder out = new StringBuilder();
    int buffer = 0;
    int bits = 0;
    for (byte value : bytes) {
      buffer = (buffer << 8) | (value & 0xff);
      bits += 8;
      while (bits >= 5) {
        out.append(BASE32.charAt((buffer >> (bits - 5)) & 31));
        bits -= 5;
      }
    }
    if (bits > 0) {
      out.append(BASE32.charAt((buffer << (5 - bits)) & 31));
    }
    return out.toString();
  }

  static byte[] unbase32(String text) {
    String clean = text.replaceAll("[\\s=-]", "").toUpperCase(java.util.Locale.ROOT);
    ByteBuffer out = ByteBuffer.allocate(clean.length() * 5 / 8);
    int buffer = 0;
    int bits = 0;
    for (char character : clean.toCharArray()) {
      int value = BASE32.indexOf(character);
      if (value < 0) {
        throw new IllegalArgumentException("Not base32");
      }
      buffer = (buffer << 5) | value;
      bits += 5;
      if (bits >= 8) {
        out.put((byte) (buffer >> (bits - 8)));
        bits -= 8;
      }
    }
    return out.array();
  }
}

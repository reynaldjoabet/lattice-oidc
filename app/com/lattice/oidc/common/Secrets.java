package com.lattice.oidc.common;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Random secrets: tokens, codes and IDs that an attacker must not be able to guess.
 *
 * <p>Two things this gets right that hand-written versions often don't:
 *
 * <ul>
 *   <li><b>No modulo bias.</b> Picking a character with {@code alphabet[randomByte % size]} makes
 *       some characters more likely when 256 is not a multiple of the size (with 36 characters, the
 *       first 4 come up 8/7 as often), which lowers the real entropy. {@link SecureRandom#nextInt(int)}
 *       rejects and redraws instead, so every character is equally likely.
 *   <li><b>Length from entropy.</b> A secret should be sized by the bits it must carry, not by a
 *       round number of characters: 128 bits is 22 base64url characters, 26 characters from a
 *       32-letter alphabet, or 39 decimal digits. {@link #lengthFor(int, int)} computes it exactly
 *       (with integers, not floating-point logarithms, so the boundary cases are right).
 * </ul>
 *
 * <p>One {@link SecureRandom} is shared: it is thread-safe, and on Linux and macOS the default
 * ({@code NativePRNG}) reads the kernel's generator without blocking.
 */
public final class Secrets {

  /** At least 128 bits, as NIST SP 800-63B and OWASP ask for session IDs and similar secrets. */
  public static final int DEFAULT_BITS = 128;

  /** Upper-case letters and digits without 0/O and 1/I, which people misread when typing a code. */
  public static final String UNAMBIGUOUS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

  private static final SecureRandom RANDOM = new SecureRandom();

  private Secrets() {}

  /** {@code length} random bytes. */
  public static byte[] bytes(int length) {
    if (length < 1) {
      throw new IllegalArgumentException("length must be at least 1: " + length);
    }
    byte[] bytes = new byte[length];
    RANDOM.nextBytes(bytes);
    return bytes;
  }

  /** A random base64url token (no padding) carrying {@code bits} bits, rounded up to whole bytes. */
  public static String token(int bits) {
    return Digests.base64Url(bytes((bits + 7) / 8));
  }

  /** A 128-bit random base64url token: 22 characters. */
  public static String token() {
    return token(DEFAULT_BITS);
  }

  /** {@code length} characters drawn uniformly from {@code alphabet}, which must not repeat a character. */
  public static String string(int length, String alphabet) {
    if (length < 1) {
      throw new IllegalArgumentException("length must be at least 1: " + length);
    }
    if (alphabet == null || alphabet.length() < 2 || alphabet.chars().distinct().count() != alphabet.length()) {
      throw new IllegalArgumentException("The alphabet needs at least 2 distinct characters, each once");
    }
    char[] out = new char[length];
    for (int i = 0; i < length; i++) {
      out[i] = alphabet.charAt(RANDOM.nextInt(alphabet.length()));
    }
    return new String(out);
  }

  /** Characters from {@code alphabet} enough to carry {@code bits} bits of entropy. */
  public static String stringWithBits(int bits, String alphabet) {
    return string(lengthFor(bits, alphabet.length()), alphabet);
  }

  /**
   * The fewest characters from an alphabet of {@code alphabetSize} that carry at least {@code bits}
   * bits: the smallest n with alphabetSize^n &ge; 2^bits.
   */
  public static int lengthFor(int bits, int alphabetSize) {
    if (bits < 1 || alphabetSize < 2) {
      throw new IllegalArgumentException("bits must be positive and the alphabet at least 2 characters");
    }
    BigInteger target = BigInteger.ONE.shiftLeft(bits);
    BigInteger size = BigInteger.valueOf(alphabetSize);
    BigInteger combinations = BigInteger.ONE;
    int length = 0;
    while (combinations.compareTo(target) < 0) {
      combinations = combinations.multiply(size);
      length++;
    }
    return length;
  }

  /** The entropy, in bits, of {@code length} uniform characters from an alphabet of {@code alphabetSize}. */
  public static double bits(int length, int alphabetSize) {
    return length * (Math.log(alphabetSize) / Math.log(2));
  }
}

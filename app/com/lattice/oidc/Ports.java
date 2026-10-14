package com.lattice.oidc;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Arrays;
import java.util.Set;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** The patterns from nimbus-crypto-design.md, as runnable code: `java docs/nimbus-crypto/Ports.java`. */
public final class Ports {

  // ---- 1. Fail closed on what you don't understand -------------------------------------------

  /** Must-understand policy: an unknown critical extension fails, unless the caller takes it. */
  record CritPolicy(Set<String> understood, Set<String> deferred) {
    CritPolicy {
      understood = Set.copyOf(understood);
      deferred = Set.copyOf(deferred);
    }

    boolean passes(Set<String> critical) {
      if (critical == null) return true;
      for (String name : critical) {
        if (!understood.contains(name) && !deferred.contains(name)) return false;
      }
      return true;
    }
  }

  // ---- 2. Dangerous behaviour is a named, typed opt-in -----------------------------------------

  sealed interface SignerOption permits AllowWeakKey {}

  sealed interface DecrypterOption permits AllowWeakKey, MaxInflatedLength {}

  /** One instance; its name is what shows up in code review. */
  enum AllowWeakKey implements SignerOption, DecrypterOption { INSTANCE }

  record MaxInflatedLength(int bytes) implements DecrypterOption {
    MaxInflatedLength {
      if (bytes <= 0) throw new IllegalArgumentException("bytes must be positive");
    }
  }

  static final int MIN_RSA_BITS = 2048;

  static void ensureKeySize(int keyBits, Set<? extends SignerOption> options) {
    if (keyBits < MIN_RSA_BITS && !options.contains(AllowWeakKey.INSTANCE)) {
      throw new IllegalArgumentException("The RSA key size must be at least " + MIN_RSA_BITS + " bits");
    }
  }

  // ---- 3. Make every failure look the same (Bleichenbacher / MMA) -----------------------------

  interface KeyUnwrap {
    byte[] unwrap(byte[] wrapped) throws GeneralSecurityException;
  }

  /**
   * Returns the unwrapped key, or a random key of the same length when unwrapping fails or gives
   * the wrong length. The random key is drawn first, so both paths do the same work, and the
   * failure only shows later, as an ordinary authentication-tag mismatch.
   */
  static byte[] unwrapOrRandom(KeyUnwrap unwrap, byte[] wrapped, int keyBytes, SecureRandom random) {
    byte[] fallback = new byte[keyBytes];
    random.nextBytes(fallback);
    try {
      byte[] key = unwrap.unwrap(wrapped);
      return key.length == keyBytes ? key : fallback;
    } catch (GeneralSecurityException e) {
      return fallback;
    }
  }

  // ---- 4. Authenticate before you decrypt, over length-framed input ---------------------------

  /** HMAC over aad || iv || ciphertext || bitLength(aad), as JWE's AES_CBC_HMAC_SHA2. */
  static byte[] tag(byte[] macKey, byte[] aad, byte[] iv, byte[] cipherText, int tagBytes)
      throws GeneralSecurityException {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
    mac.update(aad);
    mac.update(iv);
    mac.update(cipherText);
    mac.update(ByteBuffer.allocate(8).putLong(Math.multiplyExact((long) aad.length, 8)).array());
    return Arrays.copyOf(mac.doFinal(), tagBytes);
  }

  static byte[] decryptCbcHmac(byte[] macKey, byte[] encKey, byte[] aad, byte[] iv, byte[] cipherText, byte[] receivedTag)
      throws GeneralSecurityException {
    byte[] expected = tag(macKey, aad, iv, cipherText, 16);
    // The received tag first: the comparison's time then depends only on attacker-known data.
    if (!MessageDigest.isEqual(receivedTag, expected)) {
      throw new GeneralSecurityException("MAC check failed"); // before any padding is looked at
    }
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encKey, "AES"), new javax.crypto.spec.IvParameterSpec(iv));
    return cipher.doFinal(cipherText);
  }

  // ---- 5. Check a signature's shape before verifying it (CVE-2022-21449) ----------------------

  /** For a raw r || s ECDSA signature (JWS ES256/384/512): length, then 0 < r, s < n. */
  static boolean legalSignature(byte[] rs, ECParameterSpec curve) {
    BigInteger n = curve.getOrder();
    int half = (n.bitLength() + 7) / 8;
    if (rs.length != 2 * half) return false;
    BigInteger r = new BigInteger(1, Arrays.copyOfRange(rs, 0, half));
    BigInteger s = new BigInteger(1, Arrays.copyOfRange(rs, half, rs.length));
    return r.signum() > 0 && s.signum() > 0 && r.compareTo(n) < 0 && s.compareTo(n) < 0;
  }

  // ---- 7. Validate untrusted public keys -------------------------------------------------------

  /** Coordinates in [0, p) and y^2 = x^3 + ax + b (mod p). Nimbus checks only the equation. */
  static boolean onCurve(ECPoint point, ECParameterSpec spec) {
    if (point.equals(ECPoint.POINT_INFINITY)) return false;
    EllipticCurve curve = spec.getCurve();
    BigInteger p = ((ECFieldFp) curve.getField()).getP();
    BigInteger x = point.getAffineX();
    BigInteger y = point.getAffineY();
    if (x.signum() < 0 || x.compareTo(p) >= 0 || y.signum() < 0 || y.compareTo(p) >= 0) return false;
    BigInteger left = y.multiply(y).mod(p);
    BigInteger right = x.pow(3).add(curve.getA().multiply(x)).add(curve.getB()).mod(p);
    return left.equals(right);
  }

  // ---- 8. Bound the work an attacker can make you do -------------------------------------------

  /**
   * Inflates at most maxBytes of output: limits what a decompression bomb can allocate.
   *
   * <p>{@code end()} releases the native memory. It is called in {@code finally} rather than by
   * try-with-resources because the build targets Java 21, where Inflater is not AutoCloseable (the
   * IDE's "resource leak" warning comes from a newer JDK that does not know that).
   */
  @SuppressWarnings("resource")
  static byte[] inflate(byte[] compressed, int maxBytes) throws DataFormatException {
    Inflater inflater = new Inflater(true); // raw DEFLATE, as JWE "zip": "DEF"
    try {
      inflater.setInput(compressed);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] buffer = new byte[8192];
      while (!inflater.finished()) {
        int n = inflater.inflate(buffer);
        if (n == 0 && (inflater.needsInput() || inflater.needsDictionary())) {
          throw new DataFormatException("Truncated or invalid DEFLATE data");
        }
        if (out.size() + n > maxBytes) {
          throw new DataFormatException("Inflated data exceeds " + maxBytes + " bytes");
        }
        out.write(buffer, 0, n);
      }
      return out.toByteArray();
    } finally {
      inflater.end();
    }
  }

  static final int MAX_ITERATIONS = 1_000_000;

  static int checkedIterations(int fromHeader) {
    if (fromHeader < 1 || fromHeader > MAX_ITERATIONS) {
      throw new IllegalArgumentException("Iteration count must be 1 to " + MAX_ITERATIONS);
    }
    return fromHeader;
  }

  // ---- 9 and 11. Exact AEAD sizes; report the IV the provider really used -----------------------

  static final int IV_BYTES = 12;
  static final int TAG_BITS = 128;

  /** In/out parameter: holds the caller's IV, and afterwards the IV the cipher actually used. */
  static final class Holder<T> {
    T value;

    Holder(T value) {
      this.value = value;
    }
  }

  static byte[] encryptGcm(SecretKey key, Holder<byte[]> iv, byte[] plainText, byte[] aad)
      throws GeneralSecurityException {
    if (iv.value.length != IV_BYTES) throw new IllegalArgumentException("IV must be 96 bits");
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv.value));
    cipher.updateAAD(aad);
    byte[] out = cipher.doFinal(plainText);
    // A FIPS provider may refuse caller IVs and pick its own: tell the caller which one it was.
    AlgorithmParameters used = cipher.getParameters();
    iv.value = used.getParameterSpec(GCMParameterSpec.class).getIV();
    return out;
  }

  static byte[] decryptGcm(SecretKey key, byte[] iv, byte[] cipherTextAndTag, int tagBits, byte[] aad)
      throws GeneralSecurityException {
    // GCM accepts tags down to 32 bits; a short tag is easier to forge, so accept exactly 128.
    if (iv.length != IV_BYTES || tagBits != TAG_BITS) {
      throw new GeneralSecurityException("IV must be 96 bits and the tag 128 bits");
    }
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
    cipher.updateAAD(aad);
    return cipher.doFinal(cipherTextAndTag);
  }

  // ---- 10. A key decides what an object may do ------------------------------------------------

  enum Hmac {
    HS256(256), HS384(384), HS512(512);

    final int minKeyBits;

    Hmac(int minKeyBits) {
      this.minKeyBits = minKeyBits;
    }
  }

  record MacSigner(byte[] secret, Set<Hmac> algorithms) {
    MacSigner {
      int bits = secret.length * 8;
      if (bits < Hmac.HS256.minKeyBits) {
        throw new IllegalArgumentException("The secret must be at least 256 bits");
      }
      secret = secret.clone();
      algorithms = java.util.EnumSet.noneOf(Hmac.class);
      for (Hmac alg : Hmac.values()) {
        if (bits >= alg.minKeyBits) algorithms.add(alg);
      }
      algorithms = Set.copyOf(algorithms);
    }

    MacSigner(byte[] secret) {
      this(secret, Set.of());
    }
  }

  // ---- 13. Domain separation ------------------------------------------------------------------

  /** PBES2 salt: UTF8(alg) || 0x00 || salt, so a key derived for one algorithm is useless for another. */
  static byte[] saltFor(String alg, byte[] salt) {
    if (salt.length < 8) throw new IllegalArgumentException("The salt must be at least 8 bytes");
    byte[] name = alg.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    return ByteBuffer.allocate(name.length + 1 + salt.length).put(name).put((byte) 0).put(salt).array();
  }

  // ---- checks ---------------------------------------------------------------------------------

  static void check(boolean condition, String what) {
    if (!condition) throw new AssertionError(what);
    System.out.println("ok  " + what);
  }

  static boolean throwsAny(java.util.concurrent.Callable<?> c) {
    try {
      c.call();
      return false;
    } catch (Exception e) {
      return true;
    }
  }

  public static void main(String[] args) throws Exception {
    SecureRandom random = new SecureRandom();

    CritPolicy crit = new CritPolicy(Set.of("b64"), Set.of("exp"));
    check(crit.passes(null) && crit.passes(Set.of("b64", "exp")), "crit: known and deferred pass");
    check(!crit.passes(Set.of("b64", "unknown")), "crit: unknown fails");

    check(throwsAny(() -> { ensureKeySize(1024, Set.of()); return null; }), "weak key rejected by default");
    ensureKeySize(1024, Set.of(AllowWeakKey.INSTANCE));
    check(true, "weak key allowed only with the named option");

    byte[] good = unwrapOrRandom(w -> w, new byte[32], 32, random);
    byte[] wrongLength = unwrapOrRandom(w -> new byte[16], new byte[32], 32, random);
    byte[] failed = unwrapOrRandom(w -> { throw new javax.crypto.BadPaddingException(); }, new byte[32], 32, random);
    check(good.length == 32 && wrongLength.length == 32 && failed.length == 32, "MMA: every path yields a 32-byte key");

    byte[] macKey = new byte[32], encKey = new byte[16], iv = new byte[16], aad = "header".getBytes();
    random.nextBytes(macKey); random.nextBytes(encKey); random.nextBytes(iv);
    Cipher cbc = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cbc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encKey, "AES"), new javax.crypto.spec.IvParameterSpec(iv));
    byte[] ct = cbc.doFinal("hello".getBytes());
    byte[] t = tag(macKey, aad, iv, ct, 16);
    check(new String(decryptCbcHmac(macKey, encKey, aad, iv, ct, t)).equals("hello"), "CBC-HMAC round trip");
    byte[] tampered = ct.clone(); tampered[0] ^= 1;
    check(throwsAny(() -> decryptCbcHmac(macKey, encKey, aad, iv, tampered, t)), "CBC-HMAC: tampering fails at the MAC");
    // Framing: moving a byte from the AAD into the IV changes the tag.
    byte[] aad2 = Arrays.copyOf(aad, aad.length - 1);
    byte[] iv2 = ByteBuffer.allocate(iv.length + 1).put(aad[aad.length - 1]).put(iv).array();
    check(!Arrays.equals(t, tag(macKey, aad2, iv2, ct, 16)), "framing: same bytes, different split, different tag");

    AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
    ap.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
    ECParameterSpec p256 = ap.getParameterSpec(ECParameterSpec.class);
    check(!legalSignature(new byte[64], p256), "ECDSA: r = s = 0 rejected");
    byte[] nn = new byte[64];
    byte[] n = p256.getOrder().toByteArray();
    System.arraycopy(n, n.length - 32, nn, 0, 32);
    System.arraycopy(n, n.length - 32, nn, 32, 32);
    check(!legalSignature(nn, p256), "ECDSA: r = s = n rejected");
    java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC");
    kpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
    java.security.KeyPair kp = kpg.generateKeyPair();
    java.security.Signature es = java.security.Signature.getInstance("SHA256withECDSAinP1363Format");
    es.initSign(kp.getPrivate()); es.update("x".getBytes());
    check(legalSignature(es.sign(), p256), "ECDSA: a real signature is legal");

    ECPoint w = ((java.security.interfaces.ECPublicKey) kp.getPublic()).getW();
    check(onCurve(w, p256), "point: a real public key is on the curve");
    check(!onCurve(new ECPoint(w.getAffineX(), w.getAffineY().add(BigInteger.ONE)), p256), "point: off-curve rejected");
    BigInteger p = ((ECFieldFp) p256.getCurve().getField()).getP();
    check(!onCurve(new ECPoint(w.getAffineX().add(p), w.getAffineY()), p256), "point: x + p rejected (passes the bare equation)");

    byte[] bomb = new byte[200_000];
    int len;
    @SuppressWarnings("resource") // ended in finally: Deflater is not AutoCloseable on Java 21
    Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION, true);
    try {
      deflater.setInput(new byte[10_000_000]);
      deflater.finish();
      len = deflater.deflate(bomb);
    } finally {
      deflater.end();
    }
    byte[] bombBytes = Arrays.copyOf(bomb, len);
    check(len < 100_000, "bomb: 10 MB of zeros compresses to " + len + " bytes, under Nimbus's 100,000-byte input limit");
    check(throwsAny(() -> inflate(bombBytes, 1_000_000)), "bomb: output capped at 1 MB");
    check(inflate(bombBytes, 10_000_000).length == 10_000_000, "inflate: within the limit it works");
    check(throwsAny(() -> checkedIterations(2_000_000_000)), "p2c: huge iteration count rejected");

    SecretKey aes = new SecretKeySpec(encKey, "AES");
    byte[] gcmIv = new byte[12]; random.nextBytes(gcmIv);
    Holder<byte[]> holder = new Holder<>(gcmIv.clone());
    byte[] sealed = encryptGcm(aes, holder, "hi".getBytes(), aad);
    check(Arrays.equals(holder.value, gcmIv), "GCM: holder reports the IV used");
    check(new String(decryptGcm(aes, holder.value, sealed, 128, aad)).equals("hi"), "GCM round trip");
    check(throwsAny(() -> decryptGcm(aes, holder.value, sealed, 64, aad)), "GCM: 64-bit tag rejected");

    check(new MacSigner(new byte[48]).algorithms().equals(Set.of(Hmac.HS256, Hmac.HS384)), "MAC: 384-bit key allows HS256 and HS384 only");
    check(throwsAny(() -> new MacSigner(new byte[16])), "MAC: 128-bit key rejected");

    check(!Arrays.equals(saltFor("PBES2-HS256+A128KW", new byte[8]), saltFor("PBES2-HS512+A256KW", new byte[8])), "salt: algorithm-bound");
  }
}

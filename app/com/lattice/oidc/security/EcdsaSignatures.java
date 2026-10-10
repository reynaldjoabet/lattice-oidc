package com.lattice.oidc.security;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Converts ECDSA signatures between the two formats in use: the fixed-length {@code R || S} of JOSE
 * (RFC 7518, section 3.4: ES256, ES384, ES512 in JWS) and the ASN.1 DER {@code SEQUENCE { INTEGER r,
 * INTEGER s }} that {@link java.security.Signature} produces and expects for {@code SHA256withECDSA}
 * and the like.
 *
 * <p>Getting this wrong fails in quiet ways, so both directions are strict:
 *
 * <ul>
 *   <li><b>Zero values are refused.</b> r and s must be at least 1. Java 15 to 18 accepted r = s = 0
 *       as a valid signature for any message and key (CVE-2022-21449, "psychic signatures"); refusing
 *       zeros here protects a verifier even on such a runtime.
 *   <li><b>The JOSE length must be exactly right</b> for the algorithm: 64, 96 or 132 bytes. A
 *       shorter signature is not padded and a longer one is not cut: either would let a malformed
 *       signature through to the verifier.
 *   <li><b>DER is parsed as DER</b>, not as lenient BER: one encoding per value (minimal lengths and
 *       minimal integers, no negative numbers, nothing after the sequence), and integers larger than
 *       the curve allows are refused rather than truncated. Signatures that only differ in encoding
 *       would otherwise all verify (signature malleability), which breaks anything that uses a
 *       signature as an identifier or a replay-cache key.
 *   <li><b>P-521 lengths are handled</b>: its sequence can exceed 127 bytes, so its length takes the
 *       long form ({@code 0x81 nn}), which simple converters forget.
 * </ul>
 */
public final class EcdsaSignatures {

  private EcdsaSignatures() {}

  /** The length of a JOSE ECDSA signature for {@code alg}: ES256 and ES256K 64, ES384 96, ES512 132. */
  public static int joseLength(String alg) {
    return switch (alg) {
      case "ES256", "ES256K" -> 64;
      case "ES384" -> 96;
      case "ES512" -> 132;
      default -> throw new IllegalArgumentException("Not an ECDSA algorithm: " + alg);
    };
  }

  /** JOSE {@code R || S} to DER, for {@link java.security.Signature#verify(byte[])}. */
  public static byte[] toDer(byte[] jose, String alg) {
    int length = joseLength(alg);
    if (jose == null || jose.length != length) {
      throw new IllegalArgumentException("An " + alg + " signature is " + length + " bytes");
    }
    int half = length / 2;
    BigInteger r = new BigInteger(1, Arrays.copyOfRange(jose, 0, half));
    BigInteger s = new BigInteger(1, Arrays.copyOfRange(jose, half, length));
    requirePositive(r, s);

    byte[] rBytes = r.toByteArray(); // minimal two's complement: a leading 0x00 only when needed
    byte[] sBytes = s.toByteArray();
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    writeTlv(body, 0x02, rBytes);
    writeTlv(body, 0x02, sBytes);
    ByteArrayOutputStream der = new ByteArrayOutputStream();
    writeTlv(der, 0x30, body.toByteArray());
    return der.toByteArray();
  }

  /** DER, as {@link java.security.Signature#sign()} returns it, to JOSE {@code R || S}. */
  public static byte[] toJose(byte[] der, String alg) {
    int length = joseLength(alg);
    int half = length / 2;
    Reader in = new Reader(der);
    in.expect(0x30);
    int sequenceLength = in.length();
    if (sequenceLength != in.remaining()) {
      throw malformed("the sequence length does not match the signature");
    }
    BigInteger r = in.integer();
    BigInteger s = in.integer();
    if (in.remaining() != 0) {
      throw malformed("there are bytes after the sequence");
    }
    requirePositive(r, s);
    byte[] jose = new byte[length];
    copyFixed(r, jose, 0, half);
    copyFixed(s, jose, half, half);
    return jose;
  }

  private static void requirePositive(BigInteger r, BigInteger s) {
    if (r.signum() <= 0 || s.signum() <= 0) {
      throw new IllegalArgumentException("Invalid ECDSA signature: r and s must be at least 1");
    }
  }

  private static void copyFixed(BigInteger value, byte[] out, int offset, int size) {
    byte[] bytes = value.toByteArray();
    int start = bytes.length > 1 && bytes[0] == 0 ? 1 : 0; // drop the sign byte
    int count = bytes.length - start;
    if (count > size) {
      throw malformed("an integer is larger than the curve allows");
    }
    System.arraycopy(bytes, start, out, offset + size - count, count);
  }

  private static void writeTlv(ByteArrayOutputStream out, int tag, byte[] value) {
    out.write(tag);
    if (value.length < 0x80) {
      out.write(value.length);
    } else if (value.length <= 0xff) {
      out.write(0x81);
      out.write(value.length);
    } else {
      throw new IllegalArgumentException("Value too long for an ECDSA signature");
    }
    out.writeBytes(value);
  }

  private static IllegalArgumentException malformed(String why) {
    return new IllegalArgumentException("Invalid DER ECDSA signature: " + why);
  }

  /** A strict reader for the small subset of DER an ECDSA signature uses. */
  private static final class Reader {
    private final byte[] bytes;
    private int position;

    Reader(byte[] bytes) {
      if (bytes == null) {
        throw malformed("it is empty");
      }
      this.bytes = bytes;
    }

    int remaining() {
      return bytes.length - position;
    }

    int next() {
      if (position >= bytes.length) {
        throw malformed("it ends early");
      }
      return bytes[position++] & 0xff;
    }

    void expect(int tag) {
      if (next() != tag) {
        throw malformed("unexpected tag");
      }
    }

    /** A definite length in its shortest form: one byte below 128, else 0x81 and one byte. */
    int length() {
      int first = next();
      if (first < 0x80) {
        return first;
      }
      if (first == 0x81) {
        int value = next();
        if (value < 0x80) {
          throw malformed("a length is not in its shortest form");
        }
        return value;
      }
      throw malformed("unsupported length encoding");
    }

    BigInteger integer() {
      expect(0x02);
      int length = length();
      if (length == 0 || length > remaining()) {
        throw malformed("an integer has a bad length");
      }
      byte[] value = Arrays.copyOfRange(bytes, position, position + length);
      position += length;
      if ((value[0] & 0x80) != 0) {
        throw malformed("an integer is negative");
      }
      if (length > 1 && value[0] == 0 && (value[1] & 0x80) == 0) {
        throw malformed("an integer has a superfluous leading zero");
      }
      return new BigInteger(value);
    }
  }
}

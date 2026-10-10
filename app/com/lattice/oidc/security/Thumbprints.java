package com.lattice.oidc.security;

import com.lattice.oidc.common.Digests;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * SHA-256 thumbprints of public keys and certificates: the values OAuth uses to bind a token to a key.
 *
 * <ul>
 *   <li>{@link #of(PublicKey)} and {@link #ofJwk(Map)}: the JWK thumbprint of RFC 7638. It is the
 *       {@code jkt} of DPoP (RFC 9449: {@code dpop_jkt} and {@code cnf.jkt}), and a stable {@code kid}
 *       for a key that has none.
 *   <li>{@link #ofCertificate(X509Certificate)}: the {@code x5t#S256} of a certificate, the {@code
 *       cnf} value of a certificate-bound token (RFC 8705, section 3.1).
 *   <li>{@link #matches(String, String)}: compares two thumbprints in constant time.
 * </ul>
 *
 * <p>Why the RFC 7638 thumbprint is computed here, not by hashing the JWK as received: two JWKs of the
 * same key can differ in member order, whitespace, extra members ({@code kid}, {@code use}, {@code
 * alg}) and, for a private key, the private members. RFC 7638 hashes a canonical form that only has
 * the required public members, in lexicographic order, with no whitespace. So the same key always
 * has the same thumbprint, and a private JWK has the thumbprint of its public half, never one that
 * depends on (and so reveals a hash of) its private part.
 *
 * <p>Two encoding rules that hand-written versions often get wrong, and that make the thumbprint
 * differ from every other implementation's:
 *
 * <ul>
 *   <li>RSA {@code n} and {@code e} are unsigned and minimal: {@link BigInteger#toByteArray()} adds a
 *       zero sign byte when the top bit is set, which must be dropped (RFC 7518, section 6.3.1.1).
 *   <li>EC {@code x} and {@code y} are the full size of the curve's field, left-padded with zeros: a
 *       coordinate that happens to start with a zero byte keeps it (RFC 7518, section 6.2.1.2).
 * </ul>
 *
 * <p>Symmetric ({@code oct}) keys are refused: a thumbprint is published, and the thumbprint of a
 * secret key is a hash of the secret.
 */
public final class Thumbprints {

  /** The required members of each key type (RFC 7638, section 3.2), besides {@code kty}. */
  private static final Map<String, List<String>> REQUIRED_MEMBERS =
      Map.of(
          "RSA", List.of("e", "n"),
          "EC", List.of("crv", "x", "y"),
          "OKP", List.of("crv", "x"));

  /** The JOSE name and the JDK name of each supported EC curve. */
  private static final List<NamedCurve> EC_CURVES =
      List.of(
          NamedCurve.of("P-256", "secp256r1"),
          NamedCurve.of("P-384", "secp384r1"),
          NamedCurve.of("P-521", "secp521r1"));

  private Thumbprints() {}

  /**
   * The RFC 7638 SHA-256 thumbprint of an RSA, EC (P-256, P-384, P-521) or OKP (Ed25519, Ed448,
   * X25519, X448) public key, base64url-encoded.
   *
   * @throws IllegalArgumentException for any other kind of key
   */
  public static String of(PublicKey key) {
    return ofJwk(publicMembers(key));
  }

  /**
   * The RFC 7638 SHA-256 thumbprint of a JWK given as its JSON members (for example the {@code jwk}
   * header of a DPoP proof), base64url-encoded. Only the required members are used, so {@code kid},
   * {@code use} and private members make no difference.
   *
   * @throws IllegalArgumentException if the key type is missing, symmetric or unknown, or a required
   *     member is missing or not a string
   */
  public static String ofJwk(Map<String, ?> jwk) {
    Object kty = jwk.get("kty");
    if (!(kty instanceof String type)) {
      throw new IllegalArgumentException("The JWK has no \"kty\"");
    }
    List<String> required = REQUIRED_MEMBERS.get(type);
    if (required == null) {
      throw new IllegalArgumentException("No thumbprint for keys of type \"" + type + "\"");
    }
    // Lexicographic order of the member names, as RFC 7638 requires; TreeMap sorts by String order,
    // which is the same as Unicode code point order for these ASCII names.
    TreeMap<String, String> members = new TreeMap<>();
    members.put("kty", type);
    for (String name : required) {
      Object value = jwk.get(name);
      if (!(value instanceof String text) || text.isEmpty()) {
        throw new IllegalArgumentException("The " + type + " JWK has no \"" + name + "\"");
      }
      members.put(name, text);
    }
    return Digests.base64Url(Digests.sha256(canonicalJson(members).getBytes(StandardCharsets.UTF_8)));
  }

  /** The {@code x5t#S256} of a certificate: SHA-256 of its DER encoding, base64url-encoded. */
  public static String ofCertificate(X509Certificate certificate) {
    try {
      return Digests.base64Url(Digests.sha256(certificate.getEncoded()));
    } catch (CertificateEncodingException e) {
      throw new IllegalArgumentException("The certificate cannot be DER-encoded", e);
    }
  }

  /**
   * Whether two thumbprints are the same, in time that does not depend on where they differ. False if
   * either is null.
   */
  public static boolean matches(String expected, String actual) {
    if (expected == null || actual == null) {
      return false;
    }
    return MessageDigest.isEqual(
        expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8));
  }

  /** The required public JWK members of {@code key} (package-private for the test). */
  static Map<String, String> publicMembers(PublicKey key) {
    if (key instanceof RSAPublicKey rsa) {
      return Map.of(
          "kty", "RSA",
          "n", Digests.base64Url(unsigned(rsa.getModulus())),
          "e", Digests.base64Url(unsigned(rsa.getPublicExponent())));
    }
    if (key instanceof ECPublicKey ec) {
      ECParameterSpec params = ec.getParams();
      String crv = curveName(params);
      int size = (params.getCurve().getField().getFieldSize() + 7) / 8;
      return Map.of(
          "kty", "EC",
          "crv", crv,
          "x", Digests.base64Url(fixedLength(ec.getW().getAffineX(), size)),
          "y", Digests.base64Url(fixedLength(ec.getW().getAffineY(), size)));
    }
    Okp okp = Okp.from(key.getEncoded());
    if (okp != null) {
      return Map.of("kty", "OKP", "crv", okp.crv(), "x", Digests.base64Url(okp.x()));
    }
    throw new IllegalArgumentException("No thumbprint for " + key.getAlgorithm() + " keys");
  }

  private static String curveName(ECParameterSpec params) {
    for (NamedCurve curve : EC_CURVES) {
      if (curve.matches(params)) {
        return curve.crv();
      }
    }
    throw new IllegalArgumentException("Unsupported EC curve: " + params.getCurve());
  }

  /** The unsigned big-endian bytes of a positive number, with no leading zero byte. */
  private static byte[] unsigned(BigInteger value) {
    byte[] bytes = value.toByteArray();
    return bytes.length > 1 && bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
  }

  /** The unsigned big-endian bytes of a coordinate, left-padded with zeros to {@code length}. */
  private static byte[] fixedLength(BigInteger value, int length) {
    byte[] bytes = unsigned(value);
    if (bytes.length > length) {
      throw new IllegalArgumentException("The coordinate is larger than the curve allows");
    }
    byte[] out = new byte[length];
    System.arraycopy(bytes, 0, out, length - bytes.length, bytes.length);
    return out;
  }

  /**
   * {"a":"…","b":"…"} with no whitespace. The values are base64url, curve names or key types, but are
   * still escaped as JSON strings so that an odd value from a received JWK cannot change the structure.
   */
  private static String canonicalJson(TreeMap<String, String> members) {
    StringBuilder json = new StringBuilder("{");
    members.forEach(
        (name, value) -> {
          if (json.length() > 1) {
            json.append(',');
          }
          appendString(json, name).append(':');
          appendString(json, value);
        });
    return json.append('}').toString();
  }

  private static StringBuilder appendString(StringBuilder json, String value) {
    json.append('"');
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
        case '"' -> json.append("\\\"");
        case '\\' -> json.append("\\\\");
        default -> {
          if (c < 0x20) {
            json.append(String.format("\\u%04x", (int) c));
          } else {
            json.append(c);
          }
        }
      }
    }
    return json.append('"');
  }

  private record NamedCurve(String crv, ECParameterSpec spec) {

    static NamedCurve of(String crv, String jdkName) {
      try {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(jdkName));
        return new NamedCurve(crv, parameters.getParameterSpec(ECParameterSpec.class));
      } catch (GeneralSecurityException e) {
        throw new IllegalStateException("This JVM has no " + jdkName, e);
      }
    }

    /** Same curve, base point and order: a key from any provider (JDK or Bouncy Castle) matches. */
    boolean matches(ECParameterSpec other) {
      return spec.getCurve().equals(other.getCurve())
          && spec.getGenerator().equals(other.getGenerator())
          && spec.getOrder().equals(other.getOrder())
          && spec.getCofactor() == other.getCofactor();
    }
  }

  /**
   * An OKP public key, read from its X.509 SubjectPublicKeyInfo encoding (RFC 8410). That encoding is
   * the same from every provider, while the JDK's EdEC interfaces hold the key in a decoded form and
   * Bouncy Castle's keys don't implement them, so reading the encoding works for both.
   */
  private record Okp(String crv, byte[] x) {

    /**
     * The fixed 12-byte prefix is SEQUENCE { SEQUENCE { OID 1.3.101.n }, BIT STRING with no unused
     * bits }, followed by the raw key; n and the key length identify the curve.
     */
    static Okp from(byte[] spki) {
      if (spki == null || spki.length < 12) {
        return null;
      }
      boolean prefix =
          (spki[0] & 0xff) == 0x30
              && (spki[2] & 0xff) == 0x30
              && (spki[3] & 0xff) == 0x05
              && (spki[4] & 0xff) == 0x06
              && (spki[5] & 0xff) == 0x03
              && (spki[6] & 0xff) == 0x2b
              && (spki[7] & 0xff) == 0x65
              && (spki[9] & 0xff) == 0x03
              && (spki[11] & 0xff) == 0x00;
      if (!prefix) {
        return null;
      }
      String crv;
      int length;
      switch (spki[8] & 0xff) {
        case 0x6e -> { crv = "X25519"; length = 32; }
        case 0x6f -> { crv = "X448"; length = 56; }
        case 0x70 -> { crv = "Ed25519"; length = 32; }
        case 0x71 -> { crv = "Ed448"; length = 57; }
        default -> {
          return null;
        }
      }
      if (spki.length != 12 + length
          || (spki[1] & 0xff) != 10 + length
          || (spki[10] & 0xff) != length + 1) {
        return null;
      }
      return new Okp(crv, Arrays.copyOfRange(spki, 12, spki.length));
    }
  }
}

package com.lattice.oidc.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.X509CertUtils;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

/**
 * Thumbprints against the RFC test vectors, and against nimbus-jose-jwt's implementation for keys of
 * every supported type, including the encoding corner cases.
 */
public class ThumbprintsTest {

  /** RFC 7638, section 3.1: the example RSA key and its thumbprint. */
  @Test
  public void matchesTheRfc7638Example() {
    Map<String, Object> jwk =
        Map.of(
            "kty", "RSA",
            "n",
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECP"
                    + "ebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q"
                    + "vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQF"
                    + "h6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e", "AQAB",
            "alg", "RS256",
            "kid", "2011-04-29");
    assertEquals("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", Thumbprints.ofJwk(jwk));
  }

  /** RFC 8037, appendix A.3: the Ed25519 key of appendix A.1, built as a JDK key. */
  @Test
  public void matchesTheRfc8037Ed25519Example() throws Exception {
    byte[] x = Base64.getUrlDecoder().decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
    byte[] prefix = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
    byte[] spki = new byte[prefix.length + x.length];
    System.arraycopy(prefix, 0, spki, 0, prefix.length);
    System.arraycopy(x, 0, spki, prefix.length, x.length);
    PublicKey key = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));

    assertEquals("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", Thumbprints.of(key));
  }

  @Test
  public void rsaKeysMatchNimbus() throws Exception {
    for (int bits : new int[] {2048, 3072}) {
      RSAPublicKey key = (RSAPublicKey) generate("RSA", bits).getPublic();
      assertEquals(nimbus(key), Thumbprints.of(key));
    }
  }

  @Test
  public void ecKeysOnEveryCurveMatchNimbus() throws Exception {
    for (String curve : new String[] {"secp256r1", "secp384r1", "secp521r1"}) {
      ECPublicKey key = (ECPublicKey) generateEc(curve, null).getPublic();
      assertEquals(curve, nimbus(key), Thumbprints.of(key));
    }
  }

  /** A coordinate that starts with a zero byte keeps it: x is always the field size. */
  @Test
  public void anEcCoordinateWithALeadingZeroIsPadded() throws Exception {
    ECPublicKey key = null;
    for (int i = 0; i < 20_000 && key == null; i++) {
      ECPublicKey candidate = (ECPublicKey) generateEc("secp256r1", null).getPublic();
      if (candidate.getW().getAffineX().bitLength() <= 248) {
        key = candidate;
      }
    }
    assertTrue("no key with a short x coordinate was generated", key != null);
    assertEquals(43, Thumbprints.publicMembers(key).get("x").length()); // 32 bytes, base64url
    assertEquals(nimbus(key), Thumbprints.of(key));
  }

  /** Keys from Bouncy Castle carry their own parameter classes; the curve is still recognised. */
  @Test
  public void bouncyCastleKeysHaveTheSameThumbprints() throws Exception {
    ECPublicKey ec = (ECPublicKey) generateEc("secp384r1", new BouncyCastleProvider()).getPublic();
    assertEquals(nimbus(ec), Thumbprints.of(ec));

    PublicKey jdk = generate("Ed25519", 0).getPublic();
    PublicKey bc =
        KeyFactory.getInstance("Ed25519", new BouncyCastleProvider())
            .generatePublic(new X509EncodedKeySpec(jdk.getEncoded()));
    assertEquals(Thumbprints.of(jdk), Thumbprints.of(bc));
  }

  @Test
  public void everyOkpCurveIsRecognised() throws Exception {
    Map<String, String> expected = Map.of("Ed25519", "Ed25519", "Ed448", "Ed448", "X25519", "X25519", "X448", "X448");
    Map<String, Integer> sizes = Map.of("Ed25519", 32, "Ed448", 57, "X25519", 32, "X448", 56);
    for (String algorithm : expected.keySet()) {
      Map<String, String> members = Thumbprints.publicMembers(generate(algorithm, 0).getPublic());
      assertEquals("OKP", members.get("kty"));
      assertEquals(expected.get(algorithm), members.get("crv"));
      assertEquals(
          algorithm, (int) sizes.get(algorithm), Base64.getUrlDecoder().decode(members.get("x")).length);
    }
  }

  /** Only the required public members count: kid, use, alg and the private part change nothing. */
  @Test
  public void aPrivateJwkHasTheThumbprintOfItsPublicKey() throws Exception {
    KeyPair pair = generate("RSA", 2048);
    RSAKey full =
        new RSAKey.Builder((RSAPublicKey) pair.getPublic())
            .privateKey((RSAPrivateKey) pair.getPrivate())
            .keyID("signing-1")
            .build();
    assertEquals(Thumbprints.of(pair.getPublic()), Thumbprints.ofJwk(full.toJSONObject()));
  }

  @Test
  public void differentKeysHaveDifferentThumbprints() throws Exception {
    assertNotEquals(
        Thumbprints.of(generate("Ed25519", 0).getPublic()),
        Thumbprints.of(generate("Ed25519", 0).getPublic()));
  }

  @Test
  public void symmetricAndIncompleteKeysAreRefused() {
    assertThrows(IllegalArgumentException.class, () -> Thumbprints.ofJwk(Map.of("kty", "oct", "k", "c2VjcmV0")));
    assertThrows(IllegalArgumentException.class, () -> Thumbprints.ofJwk(Map.of("kty", "EC", "crv", "P-256", "x", "AA")));
    assertThrows(IllegalArgumentException.class, () -> Thumbprints.ofJwk(Map.of("n", "AA", "e", "AQAB")));
    assertThrows(IllegalArgumentException.class, () -> Thumbprints.ofJwk(Map.of("kty", "RSA", "n", 1, "e", "AQAB")));
  }

  @Test
  public void certificateThumbprintsMatchNimbus() throws Exception {
    X509Certificate certificate =
        (X509Certificate)
            CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(ObbTestPki.LEAF.getBytes(StandardCharsets.US_ASCII)));
    assertEquals(
        X509CertUtils.computeSHA256Thumbprint(certificate).toString(),
        Thumbprints.ofCertificate(certificate));
  }

  @Test
  public void matchesComparesWholeValues() {
    assertTrue(Thumbprints.matches("abc", "abc"));
    assertFalse(Thumbprints.matches("abc", "abd"));
    assertFalse(Thumbprints.matches("abc", "abcd"));
    assertFalse(Thumbprints.matches(null, "abc"));
    assertFalse(Thumbprints.matches("abc", null));
  }

  private static KeyPair generate(String algorithm, int bits) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
    if (bits > 0) {
      generator.initialize(bits);
    }
    return generator.generateKeyPair();
  }

  private static KeyPair generateEc(String curve, java.security.Provider provider) throws Exception {
    KeyPairGenerator generator =
        provider == null ? KeyPairGenerator.getInstance("EC") : KeyPairGenerator.getInstance("EC", provider);
    generator.initialize(new ECGenParameterSpec(curve));
    return generator.generateKeyPair();
  }

  private static String nimbus(RSAPublicKey key) throws Exception {
    return new RSAKey.Builder(key).build().computeThumbprint().toString();
  }

  private static String nimbus(ECPublicKey key) throws Exception {
    return new ECKey.Builder(Curve.forECParameterSpec(key.getParams()), key).build().computeThumbprint().toString();
  }
}

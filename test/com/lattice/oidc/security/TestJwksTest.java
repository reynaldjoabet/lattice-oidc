package com.lattice.oidc.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.Test;

/** The sample keys are well-formed and usable, so a test that builds on them can trust them. */
public class TestJwksTest {

  @Test
  public void everyKeyHasItsPrivatePartAndAPublicHalfWithout() {
    for (String json : TestJwks.ALL) {
      JWK key = TestJwks.parse(json);
      assertTrue(key.getKeyID(), key.isPrivate());
      JWK shared = key.toPublicJWK();
      assertFalse(key.getKeyID(), shared.isPrivate());
      assertFalse(key.getKeyID(), shared.toJSONString().contains("\"d\""));
      assertEquals(key.getKeyID(), shared.getKeyID());
    }
    assertEquals(TestJwks.ALL.size(), TestJwks.publicSet().getKeys().size());
    assertFalse(TestJwks.publicSet().toString(true).contains("\"d\""));
  }

  /** Our thumbprints of every sample key (private or public form) are the library's, for RSA and each EC curve. */
  @Test
  public void thumbprintsMatchTheLibraryForEveryKey() throws Exception {
    java.util.Set<String> seen = new java.util.HashSet<>();
    for (String json : TestJwks.ALL) {
      JWK key = TestJwks.parse(json);
      String expected = key.computeThumbprint().toString();
      assertEquals(key.getKeyID(), expected, Thumbprints.ofJwk(key.toJSONObject()));
      assertEquals(key.getKeyID(), expected, Thumbprints.ofJwk(key.toPublicJWK().toJSONObject()));
      assertTrue("distinct keys have distinct thumbprints", seen.add(expected));
    }
  }

  @Test
  public void theSigningKeysSignAndVerify() throws Exception {
    RSAKey rsa = (RSAKey) TestJwks.parse(TestJwks.RSA_SIGNING);
    JWSObject signed = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsa.getKeyID()).build(), new Payload("hello"));
    signed.sign(new RSASSASigner(rsa));
    assertTrue(JWSObject.parse(signed.serialize()).verify(new RSASSAVerifier(rsa.toRSAPublicKey())));

    ECKey ec = (ECKey) TestJwks.parse(TestJwks.EC_P256_SIGNING);
    JWSObject es = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ec.getKeyID()).build(), new Payload("hello"));
    es.sign(new ECDSASigner(ec));
    assertTrue(JWSObject.parse(es.serialize()).verify(new ECDSAVerifier(ec.toECPublicKey())));
    ECKey other = new com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).generate();
    assertFalse("another key must not verify", JWSObject.parse(es.serialize()).verify(new ECDSAVerifier(other.toECPublicKey())));
  }

  @Test
  public void theEncryptionKeysEncryptAndDecrypt() throws Exception {
    RSAKey rsa = (RSAKey) TestJwks.parse(TestJwks.RSA_ENCRYPTION);
    JWEObject sealed = new JWEObject(new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM), new Payload("secret"));
    sealed.encrypt(new RSAEncrypter(rsa.toRSAPublicKey()));
    JWEObject opened = JWEObject.parse(sealed.serialize());
    opened.decrypt(new RSADecrypter(rsa));
    assertEquals("secret", opened.getPayload().toString());

    String[] ecKeys = {
      TestJwks.EC_P384_ECDH_ES, TestJwks.EC_P384_ECDH_ES_A128KW, TestJwks.EC_P384_ECDH_ES_A192KW, TestJwks.EC_P521_ECDH_ES_A192KW
    };
    for (String json : ecKeys) {
      ECKey ec = (ECKey) TestJwks.parse(json);
      JWEAlgorithm alg = JWEAlgorithm.parse(ec.getAlgorithm().getName());
      JWEObject box = new JWEObject(new JWEHeader(alg, EncryptionMethod.A256GCM), new Payload("secret"));
      box.encrypt(new ECDHEncrypter(ec.toPublicJWK().toECKey()));
      JWEObject read = JWEObject.parse(box.serialize());
      read.decrypt(new ECDHDecrypter(ec));
      assertEquals(ec.getKeyID(), "secret", read.getPayload().toString());
    }
  }

  @Test
  public void keyUsesAndAlgorithmsMatchWhatTheKeysAreFor() {
    for (String json : TestJwks.ALL) {
      JWK key = TestJwks.parse(json);
      boolean encryption = key.getKeyUse() == KeyUse.ENCRYPTION;
      String alg = key.getAlgorithm().getName();
      if (encryption) {
        assertTrue(alg, JoseAlgorithms.keyEncryptionProblem("test key", alg).isEmpty());
      } else {
        assertTrue(alg, JoseAlgorithms.signingProblem("test key", alg).isEmpty());
      }
    }
  }
}

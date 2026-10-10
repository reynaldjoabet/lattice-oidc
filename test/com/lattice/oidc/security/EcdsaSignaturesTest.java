package com.lattice.oidc.security;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.nimbusds.jose.crypto.impl.ECDSA;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Map;
import org.junit.Test;

public class EcdsaSignaturesTest {

  private static final Map<String, String[]> CURVES =
      Map.of(
          "ES256", new String[] {"secp256r1", "SHA256withECDSA"},
          "ES384", new String[] {"secp384r1", "SHA384withECDSA"},
          "ES512", new String[] {"secp521r1", "SHA512withECDSA"});

  /** Many signatures per curve, so short r and s values (leading zero bytes) are covered too. */
  @Test
  public void roundTripsAndVerifiesOnEveryCurve() throws Exception {
    byte[] message = "message".getBytes(StandardCharsets.UTF_8);
    for (Map.Entry<String, String[]> entry : CURVES.entrySet()) {
      String alg = entry.getKey();
      KeyPair pair = keyPair(entry.getValue()[0]);
      for (int i = 0; i < 200; i++) {
        Signature signer = Signature.getInstance(entry.getValue()[1]);
        signer.initSign(pair.getPrivate());
        signer.update(message);
        byte[] der = signer.sign();

        byte[] jose = EcdsaSignatures.toJose(der, alg);
        assertEquals(EcdsaSignatures.joseLength(alg), jose.length);
        assertArrayEquals(ECDSA.transcodeSignatureToConcat(der, jose.length), jose);
        assertArrayEquals(der, EcdsaSignatures.toDer(jose, alg));

        Signature verifier = Signature.getInstance(entry.getValue()[1]);
        verifier.initVerify(pair.getPublic());
        verifier.update(message);
        assertTrue(verifier.verify(EcdsaSignatures.toDer(jose, alg)));
      }
    }
  }

  /** CVE-2022-21449: r = s = 0 is refused before it reaches the verifier. */
  @Test
  public void refusesZeroSignatures() {
    assertThrows(IllegalArgumentException.class, () -> EcdsaSignatures.toDer(new byte[64], "ES256"));
    byte[] zeroS = new byte[64];
    zeroS[31] = 1;
    assertThrows(IllegalArgumentException.class, () -> EcdsaSignatures.toDer(zeroS, "ES256"));
    assertThrows(IllegalArgumentException.class, () -> EcdsaSignatures.toJose(new byte[] {0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01}, "ES256"));
  }

  @Test
  public void refusesWrongLengthsAndNonDerEncodings() {
    assertThrows(IllegalArgumentException.class, () -> EcdsaSignatures.toDer(new byte[63], "ES256"));
    assertThrows(IllegalArgumentException.class, () -> EcdsaSignatures.toDer(new byte[96], "ES256"));
    assertThrows(IllegalArgumentException.class, () -> EcdsaSignatures.toDer(new byte[64], "RS256"));
    // a superfluous leading zero
    assertThrows(IllegalArgumentException.class, () -> EcdsaSignatures.toJose(new byte[] {0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01}, "ES256"));
    // a negative integer
    assertThrows(IllegalArgumentException.class, () -> EcdsaSignatures.toJose(new byte[] {0x30, 0x06, 0x02, 0x01, (byte) 0x81, 0x02, 0x01, 0x01}, "ES256"));
    // a long-form length where the short form fits
    assertThrows(IllegalArgumentException.class, () -> EcdsaSignatures.toJose(new byte[] {0x30, (byte) 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, "ES256"));
    // trailing bytes, and a sequence length that doesn't match
    assertThrows(IllegalArgumentException.class, () -> EcdsaSignatures.toJose(new byte[] {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00}, "ES256"));
    // an integer larger than the curve: 34 bytes of value for P-256's 32
    byte[] big = new byte[2 + 2 + 34 + 3];
    big[0] = 0x30; big[1] = (byte) (big.length - 2); big[2] = 0x02; big[3] = 34; big[4] = 0x7f;
    big[38] = 0x02; big[39] = 0x01; big[40] = 0x01;
    assertThrows(IllegalArgumentException.class, () -> EcdsaSignatures.toJose(big, "ES256"));
  }

  private static KeyPair keyPair(String curve) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec(curve));
    return generator.generateKeyPair();
  }
}

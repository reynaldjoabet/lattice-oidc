package com.lattice.oidc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.lattice.oidc.security.Thumbprints;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.junit.Test;

/** Server-side DPoP proof verification for each allowed key type, and replay. */
public class DPoPTest {

  private static final URI TOKEN = URI.create("https://as.example/api/token");

  @Test
  public void verifiesAnEs256Proof() throws Exception {
    ECKey key = new ECKeyGenerator(Curve.P_256).generate();
    String proof = DPoP.createProof(key, "POST", TOKEN, null, null);
    DPoP.Verified verified = new DPoP().verify(List.of(proof), "POST", TOKEN, null, null, null);
    assertEquals(Thumbprints.ofJwk(key.toPublicJWK().toJSONObject()), verified.jkt().toString());
  }

  /** EdDSA is in the allowed list, so an Ed25519 proof must verify too (signed here with the JDK). */
  @Test
  public void verifiesAnEd25519Proof() throws Exception {
    KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] spki = pair.getPublic().getEncoded();
    OctetKeyPair jwk =
        new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(Arrays.copyOfRange(spki, 12, spki.length))).build();

    String proof = ed25519Proof(pair, jwk, "POST");
    DPoP.Verified verified = new DPoP().verify(List.of(proof), "POST", TOKEN, null, null, null);
    assertEquals(Thumbprints.of(pair.getPublic()), verified.jkt().toString());

    // Signed by a different key than the one in the header: refused.
    KeyPair other = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String forged = ed25519Proof(other, jwk, "POST");
    assertThrows(DPoP.InvalidProof.class, () -> new DPoP().verify(List.of(forged), "POST", TOKEN, null, null, null));
  }

  private static String ed25519Proof(KeyPair signer, OctetKeyPair headerKey, String htm) throws Exception {
    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA).type(DPoP.DPOP_JWT).jwk(headerKey).build();
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .jwtID(UUID.randomUUID().toString())
            .claim("htm", htm)
            .claim("htu", TOKEN.toString())
            .issueTime(new Date())
            .build();
    String signingInput = header.toBase64URL() + "." + Base64URL.encode(claims.toString());
    Signature signature = Signature.getInstance("Ed25519");
    signature.initSign(signer.getPrivate());
    signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
    return signingInput + "." + Base64URL.encode(signature.sign());
  }

  @Test
  public void aReplayedProofIsRefused() throws Exception {
    ECKey key = new ECKeyGenerator(Curve.P_256).generate();
    String proof = DPoP.createProof(key, "POST", TOKEN, null, null);
    DPoP dpop = new DPoP();
    dpop.verify(List.of(proof), "POST", TOKEN, null, null, null);
    assertThrows(DPoP.InvalidProof.class, () -> dpop.verify(List.of(proof), "POST", TOKEN, null, null, null));
  }
}

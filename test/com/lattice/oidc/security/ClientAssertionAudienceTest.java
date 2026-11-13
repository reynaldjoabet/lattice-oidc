package com.lattice.oidc.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import java.util.List;
import java.util.Optional;
import org.junit.Test;

public class ClientAssertionAudienceTest {

  private static final String ISSUER = "https://as.example";

  static String assertion(List<String> audience) throws Exception {
    JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().issuer("client").subject("client");
    if (!audience.isEmpty()) {
      claims.audience(audience);
    }
    SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims.build());
    jwt.sign(new MACSigner(new byte[32]));
    return jwt.serialize();
  }

  @Test
  public void acceptsTheIssuerAsTheOnlyAudience() throws Exception {
    assertEquals(
        Optional.empty(), ClientAssertionAudience.problem(assertion(List.of(ISSUER)), ISSUER));
  }

  @Test
  public void refusesTheTokenEndpointUrl() throws Exception {
    assertTrue(
        ClientAssertionAudience.problem(assertion(List.of(ISSUER + "/api/token")), ISSUER)
            .isPresent());
  }

  @Test
  public void refusesTheIssuerAlongsideOtherAudiences() throws Exception {
    assertTrue(
        ClientAssertionAudience.problem(assertion(List.of(ISSUER, "https://other.example")), ISSUER)
            .isPresent());
  }

  @Test
  public void refusesAnAssertionWithoutAudience() throws Exception {
    assertTrue(ClientAssertionAudience.problem(assertion(List.of()), ISSUER).isPresent());
  }

  @Test
  public void comparesExactlyWithoutNormalisingTheUrl() throws Exception {
    assertTrue(
        ClientAssertionAudience.problem(assertion(List.of(ISSUER + "/")), ISSUER).isPresent());
  }

  @Test
  public void leavesWhatIsNotASignedJwtToAuthlete() {
    String unsigned =
        new PlainJWT(new JWTClaimsSet.Builder().audience("https://elsewhere").build()).serialize();
    assertEquals(Optional.empty(), ClientAssertionAudience.problem(unsigned, ISSUER));
    assertEquals(Optional.empty(), ClientAssertionAudience.problem("not a jwt", ISSUER));
  }
}

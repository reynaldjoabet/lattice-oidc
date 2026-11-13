package com.lattice.oidc.handlers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.nimbusds.jwt.JWTClaimsSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.Test;

/** Which ID tokens a client may exchange (RFC 8693 with an ID token as subject_token). */
public class IdTokenAudienceTest {

  private static final Set<String> CLIENT = Set.of("42", "billing-app");

  private static JWTClaimsSet idToken(List<String> audience, String azp) {
    JWTClaimsSet.Builder b = new JWTClaimsSet.Builder().subject("alice").audience(audience);
    if (azp != null) {
      b.claim("azp", azp);
    }
    return b.build();
  }

  @Test
  public void acceptsAnAudienceThatIncludesTheClient() {
    assertEquals(
        Optional.empty(),
        TokenGrantHandler.idTokenAudienceProblem(idToken(List.of("billing-app"), null), CLIENT));
    assertEquals(
        Optional.empty(),
        TokenGrantHandler.idTokenAudienceProblem(
            idToken(List.of("42", "https://api.example"), "42"), CLIENT));
  }

  @Test
  public void refusesAnIdTokenIssuedToAnotherClient() {
    assertTrue(
        TokenGrantHandler.idTokenAudienceProblem(idToken(List.of("other-app"), null), CLIENT)
            .isPresent());
  }

  @Test
  public void refusesWhenAnotherClientIsTheAuthorizedParty() {
    // The client is one of several audiences, but the ID token was requested by another client.
    assertTrue(
        TokenGrantHandler.idTokenAudienceProblem(
                idToken(List.of("other-app", "42"), "other-app"), CLIENT)
            .isPresent());
  }

  @Test
  public void refusesAnIdTokenWithoutAudience() {
    assertTrue(
        TokenGrantHandler.idTokenAudienceProblem(idToken(List.of(), null), CLIENT).isPresent());
  }
}

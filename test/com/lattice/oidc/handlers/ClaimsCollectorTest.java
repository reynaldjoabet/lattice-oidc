package com.lattice.oidc.handlers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.lattice.oidc.models.User;
import java.util.List;
import java.util.Map;
import org.junit.Test;

public class ClaimsCollectorTest {

  private final User user =
      new User(
          "s1",
          "u",
          null,
          Map.of("name", "Taro", "name#ja", "太郎", "email", "t@example.com"),
          Map.of(),
          List.of(
              Map.of(
                  "verification", Map.of("trust_framework", "de_aml"),
                  "claims", Map.of("given_name", "Taro", "family_name", "Yamada"))));

  @Test
  public void resolvesLocalesAndTags() {
    ClaimsCollector c = new ClaimsCollector(user);
    assertEquals("太郎", c.collect(new String[] {"name"}, new String[] {"ja"}).get("name"));
    assertEquals("Taro", c.collect(new String[] {"name"}, new String[] {"fr"}).get("name"));
    assertEquals("太郎", c.collect(new String[] {"name#ja"}, null).get("name#ja"));
    assertNull(c.collect(new String[] {"phone_number"}, null));
  }

  @Test
  public void addsMatchingVerifiedClaims() {
    ClaimsCollector c = new ClaimsCollector(user);
    Map<String, Object> claims =
        c.withVerifiedClaims(
            null,
            "{\"verified_claims\":{\"verification\":{\"trust_framework\":null},"
                + "\"claims\":{\"given_name\":null}}}");
    Object verified = claims.get("verified_claims");
    assertTrue(String.valueOf(verified), String.valueOf(verified).contains("given_name=Taro"));
    assertTrue(!String.valueOf(verified).contains("family_name"));
  }
}

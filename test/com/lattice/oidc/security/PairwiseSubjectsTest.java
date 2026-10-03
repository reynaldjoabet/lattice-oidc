package com.lattice.oidc.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import com.lattice.oidc.client.TestSettings;
import com.lattice.oidc.common.LatticeConfig;
import java.util.Map;
import org.junit.Test;

public class PairwiseSubjectsTest {

  @Test
  public void stablePerSectorAndUnlinkableAcrossSectors() {
    PairwiseSubjects p =
        new PairwiseSubjects(
            new LatticeConfig(TestSettings.config(Map.of("lattice.pairwise-secret", "secret"))));
    assertEquals(p.compute("a.example", "s1"), p.compute("a.example", "s1"));
    assertNotEquals(p.compute("a.example", "s1"), p.compute("b.example", "s1"));
    assertNotEquals("the user id must not be visible", "s1", p.compute("a.example", "s1"));
  }
}

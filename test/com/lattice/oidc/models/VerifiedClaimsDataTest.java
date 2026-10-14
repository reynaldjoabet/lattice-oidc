package com.lattice.oidc.models;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** The structure checks on identity-verification data an operator enters. */
public class VerifiedClaimsDataTest {

  private static final String DATASET =
      "{\"verification\":{\"trust_framework\":\"jp_aml\"},\"claims\":{\"given_name\":\"Taro\"}}";

  @Test
  public void anArrayOrASingleDatasetIsAccepted() {
    VerifiedClaimsData.Parsed array = VerifiedClaimsData.parse("[" + DATASET + "," + DATASET + "]");
    assertTrue(array.problems().toString(), array.ok());
    assertEquals(2, array.datasets().size());
    VerifiedClaimsData.Parsed single = VerifiedClaimsData.parse(DATASET);
    assertTrue(single.ok());
    assertEquals(1, single.datasets().size());
  }

  @Test
  public void emptyMeansNone() {
    VerifiedClaimsData.Parsed none = VerifiedClaimsData.parse("  ");
    assertTrue(none.ok());
    assertTrue(none.datasets().isEmpty());
    assertTrue(VerifiedClaimsData.parse("[]").ok());
  }

  @Test
  public void malformedDataIsRefusedWithAReason() {
    assertProblem("{not json", "not valid JSON");
    assertProblem("\"text\"", "JSON array");
    assertProblem("[1]", "not a JSON object");
    assertProblem("[{\"claims\":{\"given_name\":\"Taro\"}}]", "no \"verification\" object");
    assertProblem("[{\"verification\":{},\"claims\":{\"given_name\":\"Taro\"}}]", "trust_framework");
    assertProblem("[{\"verification\":{\"trust_framework\":\"jp_aml\"},\"claims\":{}}]", "no \"claims\"");
    assertProblem("[" + DATASET + ",{\"verification\":{\"trust_framework\":\"x\"}}]", "Dataset 2");
  }

  private static void assertProblem(String json, String expected) {
    VerifiedClaimsData.Parsed parsed = VerifiedClaimsData.parse(json);
    assertFalse(json, parsed.ok());
    assertTrue(parsed.problems().toString(), parsed.problems().stream().anyMatch(p -> p.contains(expected)));
    assertTrue("nothing is kept from refused data", parsed.datasets().isEmpty());
  }
}

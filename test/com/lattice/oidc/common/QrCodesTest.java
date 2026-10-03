package com.lattice.oidc.common;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class QrCodesTest {

  @Test
  public void rendersModulesAsOneSvgPathWithAnAccessibleLabel() {
    String svg = QrCodes.svg("openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fx", "Offer \"A\"");
    assertTrue(svg.startsWith("<svg"));
    assertTrue("version 1 is 21 modules; with the border the view box is larger", svg.contains("viewBox=\"0 0 "));
    assertTrue(svg.contains("h1v1h-1z"));
    assertTrue("the label is escaped", svg.contains("aria-label=\"Offer &quot;A&quot;\""));
  }
}

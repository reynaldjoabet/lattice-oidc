package com.lattice.oidc.controllers;

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.lattice.oidc.common.LatticeConfig.ResourceServer;
import java.util.Optional;
import org.junit.Test;

/** Resource-server settings for JWT introspection responses are checked when the application starts. */
public class IntrospectionSettingsTest {

  private static final String SECRET = "x".repeat(IntrospectionController.RECOMMENDED_SECRET_LENGTH);

  private static ResourceServer server(String signAlg, String encryptionAlg, String sharedKey) {
    return new ResourceServer(
        "rs1",
        SECRET,
        Optional.empty(),
        Optional.ofNullable(signAlg),
        Optional.ofNullable(encryptionAlg),
        Optional.ofNullable(encryptionAlg == null ? null : "A256GCM"),
        Optional.ofNullable(sharedKey),
        Optional.empty(),
        Optional.empty());
  }

  @Test
  public void acceptsSafeSettings() {
    IntrospectionController.check(server(null, null, null));
    IntrospectionController.check(server("PS256", "RSA-OAEP-256", null));
    IntrospectionController.check(server("HS256", null, "k".repeat(32)));
    IntrospectionController.check(server("HS512", null, "k".repeat(64)));
  }

  @Test
  public void refusesUnsafeSettings() {
    assertMessage(server("none", null, null), "introspection-sign-alg");
    assertMessage(server("PS256", "RSA1_5", null), "RSA1_5");
    assertMessage(server("PS256", "PBES2-HS256+A128KW", null), "password-based");
    assertMessage(server("HS256", null, "short-key"), "at least 32 bytes");
    assertMessage(server("HS512", null, "k".repeat(32)), "at least 64 bytes");
    assertMessage(server("HS256", null, null), "0 bytes");
  }

  private static void assertMessage(ResourceServer server, String expected) {
    IllegalStateException e = assertThrows(IllegalStateException.class, () -> IntrospectionController.check(server));
    assertTrue(e.getMessage(), e.getMessage().contains(expected));
    assertTrue(e.getMessage(), e.getMessage().contains("rs1"));
  }
}

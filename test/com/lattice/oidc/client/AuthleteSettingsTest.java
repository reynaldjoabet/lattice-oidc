package com.lattice.oidc.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.Map;
import org.junit.Test;

public class AuthleteSettingsTest {

  @Test
  public void readsDefaults() {
    AuthleteSettings s = TestSettings.settings(Map.of());
    assertEquals("https://us.authlete.com", s.baseUrl());
    assertEquals(42L, s.serviceId());
    assertTrue(s.dpopKey().isEmpty());
  }

  @Test
  public void requiresCredentials() {
    IllegalStateException e =
        assertThrows(
            IllegalStateException.class,
            () -> AuthleteSettings.from(TestSettings.config(Map.of())));
    assertTrue(e.getMessage(), e.getMessage().contains("AUTHLETE_SERVICE_APIKEY"));

    e =
        assertThrows(
            IllegalStateException.class,
            () -> TestSettings.settings(Map.of("authlete.service-id", "abc")));
    assertTrue(e.getMessage(), e.getMessage().contains("numeric"));

    e =
        assertThrows(
            IllegalStateException.class,
            () -> TestSettings.settings(Map.of("authlete.base-url", "ftp://x")));
    assertTrue(e.getMessage(), e.getMessage().contains("base-url"));
  }

  @Test
  public void toStringDoesNotLeakSecrets() {
    AuthleteSettings s =
        TestSettings.settings(
            Map.of("authlete.service-access-token", "super-secret", "authlete.dpop-key", "{}"));
    assertFalse(s.toString().contains("super-secret"));
    assertFalse(s.toString().contains("{}"));
  }
}

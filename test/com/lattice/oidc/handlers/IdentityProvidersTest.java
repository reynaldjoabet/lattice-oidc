package com.lattice.oidc.handlers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.lattice.oidc.client.TestSettings;
import com.lattice.oidc.common.LatticeConfig;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** Loading the identity providers file. */
public class IdentityProvidersTest {

  private static final String OKTA =
      "{\"id\":\"okta\",\"server\":{\"name\":\"Okta\",\"issuer\":\"https://okta.example\"},"
          + "\"client\":{\"clientId\":\"c1\",\"redirectUri\":\"https://lattice.example/api/federation/callback/okta\"}}";
  private static final String INCOMPLETE =
      "{\"id\":\"broken\",\"server\":{\"name\":\"Broken\",\"issuer\":\"https://broken.example\"}}";

  private static IdentityProviders load(String json) throws Exception {
    Path file = Files.createTempFile("identity-providers", ".json");
    file.toFile().deleteOnExit();
    Files.writeString(file, json);
    return new IdentityProviders(
        new LatticeConfig(TestSettings.config(Map.of("lattice.identity-providers.file", file.toString()))));
  }

  @Test
  public void loadsIdentityProvidersAndSkipsIncompleteEntries() throws Exception {
    IdentityProviders providers = load("{\"identityProviders\":[" + OKTA + "," + INCOMPLETE + "]}");
    assertEquals(List.of(new IdentityProviders.Link("okta", "Okta")), providers.links());
    assertTrue(providers.get("broken").isEmpty());
  }

  @Test
  public void theExampleFileLoadsEveryProvider() {
    IdentityProviders providers =
        new IdentityProviders(
            new LatticeConfig(
                TestSettings.config(
                    Map.of("lattice.identity-providers.file", "conf/identity-providers.example.json"))));
    assertEquals(
        List.of("okta", "azure", "google", "keycloak", "pingfederate", "partner-es256"),
        providers.links().stream().map(IdentityProviders.Link::id).toList());
  }

  @Test
  public void acceptsTheFederationsKeyOfJavaOauthServerFiles() throws Exception {
    IdentityProviders providers = load("{\"federations\":[" + OKTA + "]}");
    assertTrue(providers.get("okta").isPresent());
  }
}

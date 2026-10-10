package com.lattice.oidc.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Optional;
import org.junit.Test;

public class RedirectUrisTest {

  @Test
  public void acceptsOrdinaryRedirectUris() {
    for (String uri :
        List.of(
            "https://app.example/callback",
            "https://app.example:8443/cb?tenant=a",
            "http://127.0.0.1/cb",
            "http://[::1]:8080/cb",
            "http://localhost:3000/cb",
            "com.example.app:/oauth2redirect")) {
      assertEquals(uri, Optional.empty(), RedirectUris.problem(uri));
    }
  }

  @Test
  public void refusesUnsafeRedirectUris() {
    for (String uri :
        List.of(
            "",
            "/relative/cb",
            "https://app.example/cb#frag",
            "https://app.example/*",
            "http://app.example/cb",
            "https://app.example@evil.example/cb",
            "javascript:alert(1)",
            "data:text/html,hi",
            "myapp://cb",
            "https://app.example/cb/../open",
            "https://app.example/cb/..%2Fopen",
            "https://app.example/cb/%2e%2e/open",
            "https://app.example/cb/%252E%252E/open",
            "https://app.example/cb\\..\\open",
            "https://app.example/cb?code=attacker",
            "https://app.example/cb?STATE=x",
            "https://app.example/cb?a=1&iss=https%3A%2F%2Fevil",
            "https://app.example/c b")) {
      assertTrue(uri, RedirectUris.problem(uri).isPresent());
    }
  }

  @Test
  public void matchesExactlyWithoutNormalising() {
    List<String> registered = List.of("https://app.example/cb");
    assertTrue(RedirectUris.matches(registered, "https://app.example/cb"));
    assertFalse(RedirectUris.matches(registered, "https://app.example/cb/"));
    assertFalse(RedirectUris.matches(registered, "https://APP.example/cb"));
    assertFalse(RedirectUris.matches(registered, "https://app.example/cb?x=1"));
    assertFalse(RedirectUris.matches(registered, "https://app.example:443/cb"));
    assertFalse(RedirectUris.matches(registered, null));
  }

  /** RFC 8252, 7.3: any port on a loopback IP literal, but not on "localhost". */
  @Test
  public void loopbackIpsMayUseAnyPort() {
    assertTrue(RedirectUris.matches(List.of("http://127.0.0.1/cb"), "http://127.0.0.1:51004/cb"));
    assertTrue(RedirectUris.matches(List.of("http://[::1]:80/cb"), "http://[::1]:61000/cb"));
    assertFalse(RedirectUris.matches(List.of("http://127.0.0.1/cb"), "http://127.0.0.1:51004/other"));
    assertFalse(RedirectUris.matches(List.of("http://localhost/cb"), "http://localhost:51004/cb"));
    assertFalse(RedirectUris.matches(List.of("https://127.0.0.1/cb"), "https://127.0.0.1:8443/cb"));
  }

  /** Even a registered URI never matches if it would be refused now. */
  @Test
  public void aRegisteredButUnsafeUriNeverMatches() {
    assertFalse(RedirectUris.matches(List.of("https://app.example/cb?code=x"), "https://app.example/cb?code=x"));
  }
}

package com.lattice.oidc.common;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** Secrets, SecureContexts and EmailAddresses. */
public class SmallHelpersTest {

  // ---------------------------------------------------------------- Secrets

  @Test
  public void lengthForIsExactAtTheBoundaries() {
    assertEquals(22, Secrets.lengthFor(128, 64)); // base64url
    assertEquals(32, Secrets.lengthFor(128, 16)); // hex: exactly 4 bits per character
    assertEquals(26, Secrets.lengthFor(128, 32));
    assertEquals(39, Secrets.lengthFor(128, 10));
    assertEquals(1, Secrets.lengthFor(1, 2));
    assertEquals(22, Secrets.token().length());
  }

  @Test
  public void stringsUseOnlyTheAlphabetAndEveryCharacterEvenly() {
    String alphabet = "ABC"; // 256 is not a multiple of 3: a modulo would be biased
    Map<Character, Integer> counts = new HashMap<>();
    String drawn = Secrets.string(30_000, alphabet);
    for (char c : drawn.toCharArray()) {
      counts.merge(c, 1, Integer::sum);
    }
    assertEquals(3, counts.size());
    for (int count : counts.values()) {
      assertTrue("count " + count, Math.abs(count - 10_000) < 600);
    }
    assertEquals(26, Secrets.stringWithBits(128, Secrets.UNAMBIGUOUS).length());
    assertThrows(IllegalArgumentException.class, () -> Secrets.string(5, "AAB"));
    assertThrows(IllegalArgumentException.class, () -> Secrets.string(0, "AB"));
  }

  // ---------------------------------------------------------------- SecureContexts

  @Test
  public void trustworthyOriginsAreHttpsOrLoopback() {
    for (String uri : List.of("https://a.example", "wss://a.example", "http://localhost:9000", "http://app.localhost",
        "http://127.0.0.1", "http://127.8.9.10:80", "http://[::1]:8080", "http://localhost.")) {
      assertTrue(uri, SecureContexts.isPotentiallyTrustworthy(URI.create(uri)));
    }
    for (String uri : List.of("http://a.example", "http://localhost.evil.example", "http://128.0.0.1",
        "http://127.0.0.300", "http://[::2]", "ftp://localhost", "file:///etc/passwd")) {
      assertFalse(uri, SecureContexts.isPotentiallyTrustworthy(URI.create(uri)));
    }
  }

  @Test
  public void anHttpsFrameInsideAnHttpPageIsNotSecure() {
    URI page = URI.create("https://login.example/passkey");
    assertTrue(SecureContexts.isSecureContext(page, null, null));
    assertTrue(SecureContexts.isSecureContext(page, "iframe", "https://app.example/"));
    assertFalse(SecureContexts.isSecureContext(page, "iframe", "http://app.example/"));
    assertTrue(SecureContexts.isSecureContext(page, "document", "http://app.example/"));
  }

  // ---------------------------------------------------------------- EmailAddresses

  @Test
  public void acceptsRealAddresses() {
    for (String address : List.of("a@example.com", "first.last+tag@sub.example.co.uk", "o'brien@example.ie",
        "\"john..doe\"@example.org", "\"a@b\"@example.org", "user@bücher.example", "用户@例子.广告", "x@localhost")) {
      assertTrue(address, EmailAddresses.isValid(address));
    }
    assertTrue(EmailAddresses.isValid("a@[192.0.2.1]", true));
    assertTrue(EmailAddresses.isValid("a@[IPv6:2001:db8::1]", true));
  }

  @Test
  public void refusesMalformedAddresses() {
    for (String address : List.of("", "plain", "@example.com", "a@", "a..b@example.com", ".a@example.com",
        "a.@example.com", "a b@example.com", "a@example.com.", "a@-example.com", "a@exa_mple.com",
        "a@example..com", "a@example.com\r\nBcc: x@evil.example", "a@[192.0.2.1]",
        "a@[300.0.0.1]", "a".repeat(65) + "@example.com", "a@" + "b".repeat(64) + ".com",
        "a@" + "b.".repeat(130) + "com")) {
      assertFalse(address, EmailAddresses.isValid(address, address.contains("300")));
    }
  }
}

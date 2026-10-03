package com.lattice.oidc.http;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.Test;

public class RequestsTest {

  @Test
  public void encodesAndDecodesFormParameters() {
    Map<String, String[]> params = new LinkedHashMap<>();
    params.put("scope", new String[] {"openid profile"});
    params.put("resource", new String[] {"https://a/?x=1&y", "urn:b"});
    String encoded = Requests.encode(params);
    assertEquals(
        "scope=openid+profile&resource=https%3A%2F%2Fa%2F%3Fx%3D1%26y&resource=urn%3Ab", encoded);
    Map<String, String[]> decoded = Requests.decode(encoded);
    assertArrayEquals(params.get("resource"), decoded.get("resource"));
    assertArrayEquals(params.get("scope"), decoded.get("scope"));
  }
}

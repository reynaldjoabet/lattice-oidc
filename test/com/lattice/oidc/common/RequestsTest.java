package com.lattice.oidc.common;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import com.authlete.common.web.BasicCredentials;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.Test;
import play.mvc.Http;

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

  /** RFC 6749, 2.3.1: the client ID and secret are form-encoded before base64. */
  @Test
  public void basicCredentialsAreFormDecoded() {
    String header =
        "Basic "
            + Base64.getEncoder()
                .encodeToString("my%3Aclient:s%2Bcr%25t%3Ax".getBytes(StandardCharsets.UTF_8));
    BasicCredentials credentials =
        Requests.basicCredentials(new Http.RequestBuilder().header("Authorization", header).build());
    assertEquals("my:client", credentials.getUserId());
    assertEquals("s+cr%t:x", credentials.getPassword());
  }

  @Test
  public void plainSecretsAndInvalidEncodingAreKeptAsSent() {
    assertEquals("Ab-_.~09", Requests.formDecoded("Ab-_.~09"));
    assertEquals("100%", Requests.formDecoded("100%"));
    assertNull(Requests.basicCredentials(new Http.RequestBuilder().build()));
  }
}

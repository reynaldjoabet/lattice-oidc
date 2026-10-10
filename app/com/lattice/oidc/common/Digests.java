package com.lattice.oidc.common;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * SHA-256, the one digest Lattice uses: for storing the hash of a link or secret instead of the value
 * itself, and for thumbprints.
 *
 * <p>Every JDK must provide SHA-256 (it is in the list of required algorithms in {@link MessageDigest}),
 * so a missing algorithm is a broken runtime, not something a caller can handle: it is rethrown
 * unchecked here, once, instead of in every caller.
 */
public final class Digests {

  private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();

  private Digests() {}

  /** SHA-256 of the parts, in order, as if they were one byte array. */
  public static byte[] sha256(byte[]... parts) {
    MessageDigest digest = newSha256();
    for (byte[] part : parts) {
      digest.update(part);
    }
    return digest.digest();
  }

  /** SHA-256 of the UTF-8 bytes of {@code value}, base64url-encoded without padding. */
  public static String sha256Base64Url(String value) {
    return base64Url(sha256(value.getBytes(StandardCharsets.UTF_8)));
  }

  /** Base64url without padding, the encoding JOSE and OAuth use for binary values. */
  public static String base64Url(byte[] bytes) {
    return BASE64URL.encodeToString(bytes);
  }

  private static MessageDigest newSha256() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("This JVM has no SHA-256", e);
    }
  }
}

package com.lattice.oidc.security;

import com.authlete.common.types.HashAlg;
import com.authlete.common.types.JWEAlg;
import com.authlete.common.types.JWSAlg;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Which JOSE algorithms a client may ask for in its registered metadata (RFC 7591, OpenID Connect
 * Dynamic Client Registration), and which a resource server may be configured with for JWT
 * introspection responses (RFC 9701). Everything not refused here is left to the authorization
 * server's own supported lists.
 *
 * <p><b>{@code none} is refused where it removes a protection, and allowed where it doesn't.</b> Each
 * specification rules on it per member:
 *
 * <ul>
 *   <li>Refused: {@code token_endpoint_auth_signing_alg} (an unsigned client assertion authenticates
 *       nobody; OIDC Registration forbids it), {@code introspection_signed_response_alg} (RFC 9701,
 *       section 6), {@code authorization_signed_response_alg} (JARM), {@code
 *       backchannel_authentication_request_signing_alg} (CIBA).
 *   <li>Refused, more strictly than OIDC: {@code id_token_signed_response_alg}. OIDC allows {@code
 *       none} for a client that only uses the code flow, but an unsigned ID token that ever reaches
 *       the client through the browser is forgeable, and FAPI 2.0 and RFC 8725 (section 3.1) rule
 *       it out.
 *   <li>Allowed: {@code userinfo_signed_response_alg} and {@code request_object_signing_alg}. OIDC
 *       permits {@code none} for both, and it protects nothing to refuse it: an unsigned UserInfo
 *       JWT is no weaker than the plain JSON UserInfo returns by default, and an unsigned request
 *       object no weaker than ordinary query parameters.
 * </ul>
 *
 * <p><b>Key encryption: {@code RSA1_5} and {@code PBES2-*} are refused everywhere.</b> {@code RSA1_5}
 * (RSAES-PKCS1-v1_5) is open to Bleichenbacher's adaptive chosen-ciphertext attack, which recovers
 * the content encryption key from error or timing differences (RFC 8725, section 3.2); {@code
 * RSA-OAEP} and {@code RSA-OAEP-256} do the same job safely. {@code PBES2-*} derives the key from a
 * password, which suits a person typing a passphrase, not a server's keys; and a JWE header chooses
 * its own iteration count ({@code p2c}), so a crafted token can make the server run millions of
 * PBKDF2 rounds (CVE-2023-52428).
 *
 * <p><b>HMAC keys must be at least as long as the hash</b> (RFC 7518, section 3.2): 32 bytes for
 * HS256, 48 for HS384, 64 for HS512. A shorter key makes the MAC only as strong as the key.
 *
 * <p>Names are parsed with authlete-java-common's {@link JWSAlg} and {@link JWEAlg}, the enums
 * Lattice passes to Authlete, so they match what Authlete accepts: exactly, since JOSE algorithm
 * names are case-sensitive. A name neither enum knows is left for Authlete to reject.
 */
public final class JoseAlgorithms {

  /** Metadata members whose JWS algorithm must never be {@code none}. */
  static final List<String> SIGNED_MEMBERS =
      List.of(
          "id_token_signed_response_alg",
          "token_endpoint_auth_signing_alg",
          "introspection_signed_response_alg",
          "authorization_signed_response_alg",
          "backchannel_authentication_request_signing_alg");

  /** Metadata members whose value is a JWE key management algorithm. */
  static final List<String> KEY_ENCRYPTION_MEMBERS =
      List.of(
          "id_token_encrypted_response_alg",
          "userinfo_encrypted_response_alg",
          "request_object_encryption_alg",
          "introspection_encrypted_response_alg",
          "authorization_encrypted_response_alg");

  private static final EnumSet<JWEAlg> PASSWORD_BASED =
      EnumSet.of(JWEAlg.PBES2_HS256_A128KW, JWEAlg.PBES2_HS384_A192KW, JWEAlg.PBES2_HS512_A256KW);

  private JoseAlgorithms() {}

  /** Why these client metadata can't be accepted; empty if their algorithms are all allowed. */
  public static Optional<String> problem(Map<String, Object> metadata) {
    for (String member : SIGNED_MEMBERS) {
      if (metadata.get(member) instanceof String alg) {
        Optional<String> problem = signingProblem(member, alg);
        if (problem.isPresent()) {
          return problem;
        }
      }
    }
    for (String member : KEY_ENCRYPTION_MEMBERS) {
      if (metadata.get(member) instanceof String alg) {
        Optional<String> problem = keyEncryptionProblem(member, alg);
        if (problem.isPresent()) {
          return problem;
        }
      }
    }
    return Optional.empty();
  }

  /** Why {@code alg} can't be used for {@code what}, a signature that must not be {@code none}. */
  public static Optional<String> signingProblem(String what, String alg) {
    return JWSAlg.parse(alg) == JWSAlg.NONE
        ? Optional.of(what + " must not be \"none\": unsigned tokens can be forged.")
        : Optional.empty();
  }

  /** Why {@code alg} can't be used for {@code what}, a JWE key management algorithm. */
  public static Optional<String> keyEncryptionProblem(String what, String alg) {
    JWEAlg parsed = JWEAlg.parse(alg);
    if (parsed == JWEAlg.RSA1_5) {
      return Optional.of(what + " must not be RSA1_5 (open to padding-oracle attacks); use RSA-OAEP-256.");
    }
    if (parsed != null && PASSWORD_BASED.contains(parsed)) {
      return Optional.of(what + " must not be a password-based algorithm (" + alg + ").");
    }
    return Optional.empty();
  }

  /**
   * Why {@code key} (used as UTF-8 bytes) is too short for the HMAC algorithm {@code alg}; empty for
   * a long enough key or an algorithm that isn't HMAC.
   */
  public static Optional<String> hmacKeyProblem(String what, String alg, String key) {
    JWSAlg parsed = JWSAlg.parse(alg);
    if (parsed == null || !parsed.isSymmetric()) {
      return Optional.empty();
    }
    int minimum = hashBytes(parsed.getHashAlg());
    int length = key == null ? 0 : key.getBytes(StandardCharsets.UTF_8).length;
    return length < minimum
        ? Optional.of(what + " is " + length + " bytes; " + alg + " needs a key of at least " + minimum + " bytes.")
        : Optional.empty();
  }

  /** The output size of an HMAC algorithm's hash, which is also its minimum key size. */
  private static int hashBytes(HashAlg hash) {
    return switch (hash) {
      case SHA_256 -> 32;
      case SHA_384 -> 48;
      case SHA_512 -> 64;
    };
  }
}

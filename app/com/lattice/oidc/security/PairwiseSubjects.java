package com.lattice.oidc.security;

import com.authlete.common.dto.Client;
import com.authlete.common.types.SubjectType;
import com.lattice.oidc.common.LatticeConfig;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/**
 * Pairwise subject identifiers (OIDC Core §8.1): {@code base64url(HMAC-SHA256(secret, sector |
 * subject))}. Stable per sector, unlinkable across sectors, and not reversible.
 */
@Singleton
public final class PairwiseSubjects {

  private final byte[] secret;

  @Inject
  public PairwiseSubjects(LatticeConfig config) {
    this.secret = config.pairwiseSecret().getBytes(StandardCharsets.UTF_8);
  }

  /** The {@code sub} value to use for the client, or null when the client is not pairwise. */
  public String subFor(Client client, String subject) {
    if (client == null || subject == null || client.getSubjectType() != SubjectType.PAIRWISE) {
      return null;
    }
    return compute(client.getDerivedSectorIdentifier(), subject);
  }

  public String subFor(SubjectType type, String sector, String subject) {
    return type == SubjectType.PAIRWISE && subject != null ? compute(sector, subject) : null;
  }

  String compute(String sector, String subject) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(secret, "HmacSHA256"));
      byte[] h = mac.doFinal((sector + "|" + subject).getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(h);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("HmacSHA256 unavailable", e);
    }
  }
}

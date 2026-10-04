package com.lattice.oidc.stores;

import com.google.inject.ImplementedBy;
import com.lattice.oidc.common.ObbSupport;
import com.lattice.oidc.models.Consent;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Open Banking consents. A consent is kept until it expires (at most a year), or a day when it has
 * no expiry.
 */
@ImplementedBy(InMemoryConsentStore.class)
public interface ConsentStore {

  Duration MAX_TTL = Duration.ofDays(365);
  Duration DEFAULT_TTL = Duration.ofDays(1);

  Optional<Consent> find(String consentId);

  void save(Consent consent);

  void delete(String consentId);

  default Consent create(List<String> permissions, String expirationDateTime, long clientId) {
    String now = ObbSupport.now();
    Consent consent =
        new Consent(
            "urn:lattice:" + UUID.randomUUID(),
            permissions,
            "AWAITING_AUTHORISATION",
            now,
            expirationDateTime,
            now,
            clientId,
            null);
    save(consent);
    return consent;
  }

  /** When a consent with this expiry may be deleted. */
  static Instant keepUntil(String expiration) {
    Instant now = Instant.now();
    if (expiration == null) {
      return now.plus(DEFAULT_TTL);
    }
    try {
      Instant expires = Instant.parse(expiration);
      if (!expires.isAfter(now)) {
        return now.plus(Duration.ofMinutes(1));
      }
      return expires.isAfter(now.plus(MAX_TTL)) ? now.plus(MAX_TTL) : expires;
    } catch (DateTimeParseException e) {
      return now.plus(DEFAULT_TTL);
    }
  }
}

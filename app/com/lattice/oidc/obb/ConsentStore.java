package com.lattice.oidc.obb;

import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import javax.inject.Inject;
import javax.inject.Singleton;
import play.cache.SyncCacheApi;

/** Consent persistence (cache-backed; entries live until the consent expires, at most 1 year). */
@Singleton
public final class ConsentStore {

  private static final Duration MAX_TTL = Duration.ofDays(365);
  private static final Duration DEFAULT_TTL = Duration.ofDays(1);

  private final SyncCacheApi cache;

  @Inject
  public ConsentStore(SyncCacheApi cache) {
    this.cache = cache;
  }

  public Consent create(List<String> permissions, String expirationDateTime, long clientId) {
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

  public Optional<Consent> find(String consentId) {
    return consentId == null ? Optional.empty() : cache.get(key(consentId));
  }

  public void save(Consent consent) {
    cache.set(key(consent.consentId()), consent, (int) ttl(consent.expirationDateTime()).toSeconds());
  }

  public void delete(String consentId) {
    cache.remove(key(consentId));
  }

  private static Duration ttl(String expiration) {
    if (expiration == null) {
      return DEFAULT_TTL;
    }
    try {
      Duration d = Duration.between(Instant.now(), Instant.parse(expiration));
      if (d.isNegative() || d.isZero()) {
        return Duration.ofMinutes(1);
      }
      return d.compareTo(MAX_TTL) > 0 ? MAX_TTL : d;
    } catch (DateTimeParseException e) {
      return DEFAULT_TTL;
    }
  }

  private static String key(String id) {
    return "obb-consent:" + id;
  }
}

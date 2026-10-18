package com.lattice.oidc.stores.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** A row of {@code obb_consents}: an Open Banking consent, as JSON. */
@Entity
@Table(name = "obb_consents")
public class ObbConsentEntity {

  @Id
  @Column(name = "consent_id")
  String consentId;

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "consent")
  String consent;

  @Column(name = "keep_until")
  Instant keepUntil;

  /** For JPA. */
  protected ObbConsentEntity() {}

  ObbConsentEntity(String consentId, String consent, Instant keepUntil) {
    this.consentId = consentId;
    this.consent = consent;
    this.keepUntil = keepUntil;
  }
}

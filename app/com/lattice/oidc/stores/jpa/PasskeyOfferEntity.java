package com.lattice.oidc.stores.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/** A row of {@code passkey_offers}: when an account was last offered a passkey. */
@Entity
@Table(name = "passkey_offers")
public class PasskeyOfferEntity {

  @Id
  @Column(name = "subject")
  String subject;

  @Column(name = "offered_at")
  Instant offeredAt;

  /** For JPA. */
  protected PasskeyOfferEntity() {}

  PasskeyOfferEntity(String subject, Instant offeredAt) {
    this.subject = subject;
    this.offeredAt = offeredAt;
  }
}

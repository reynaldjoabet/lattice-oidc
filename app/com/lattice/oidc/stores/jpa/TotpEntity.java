package com.lattice.oidc.stores.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/** A row of {@code totp_credentials}: an account's authenticator app. */
@Entity
@Table(name = "totp_credentials")
public class TotpEntity {

  @Id
  @Column(name = "subject")
  String subject;

  @Column(name = "secret")
  String secret;

  @Column(name = "created_at")
  Instant createdAt;

  @Column(name = "last_used_step")
  long lastUsedStep;

  /** For JPA. */
  protected TotpEntity() {}

  TotpEntity(String subject, String secret, Instant createdAt, long lastUsedStep) {
    this.subject = subject;
    this.secret = secret;
    this.createdAt = createdAt;
    this.lastUsedStep = lastUsedStep;
  }
}

package com.lattice.oidc.stores.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.time.Instant;

/** A row of {@code app_consents}: what an account approved for an app, space-separated. */
@Entity
@Table(name = "app_consents")
@IdClass(AppConsentEntity.Key.class)
public class AppConsentEntity {

  @Id
  @Column(name = "subject")
  String subject;

  @Id
  @Column(name = "client_id")
  long clientId;

  @Column(name = "scopes")
  String scopes;

  @Column(name = "claims")
  String claims;

  @Column(name = "granted_at")
  Instant grantedAt;

  /** The composite primary key. */
  public record Key(String subject, long clientId) implements Serializable {}

  /** For JPA. */
  protected AppConsentEntity() {}

  AppConsentEntity(String subject, long clientId, String scopes, String claims, Instant grantedAt) {
    this.subject = subject;
    this.clientId = clientId;
    this.scopes = scopes;
    this.claims = claims;
    this.grantedAt = grantedAt;
  }
}

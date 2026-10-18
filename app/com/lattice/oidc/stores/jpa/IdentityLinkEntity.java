package com.lattice.oidc.stores.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.time.Instant;

/** A row of {@code identity_links}: an upstream account linked to a local one. */
@Entity
@Table(name = "identity_links")
@IdClass(IdentityLinkEntity.Key.class)
public class IdentityLinkEntity {

  @Id
  @Column(name = "provider_id")
  String providerId;

  @Id
  @Column(name = "external_subject")
  String externalSubject;

  @Column(name = "local_subject")
  String localSubject;

  @Column(name = "created_at", insertable = false, updatable = false)
  Instant createdAt;

  /** The composite primary key. */
  public record Key(String providerId, String externalSubject) implements Serializable {}

  /** For JPA. */
  protected IdentityLinkEntity() {}

  IdentityLinkEntity(String providerId, String externalSubject, String localSubject) {
    this.providerId = providerId;
    this.externalSubject = externalSubject;
    this.localSubject = localSubject;
  }
}

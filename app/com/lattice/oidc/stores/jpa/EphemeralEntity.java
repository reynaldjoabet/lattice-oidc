package com.lattice.oidc.stores.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.time.Instant;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** A row of {@code ephemeral}: a short-lived entry (single-use state). */
@Entity
@Table(name = "ephemeral")
@IdClass(EphemeralEntity.Key.class)
public class EphemeralEntity {

  @Id
  @Column(name = "namespace")
  String namespace;

  @Id
  @Column(name = "key")
  String entryKey;

  @Column(name = "owner")
  String owner;

  @Column(name = "subject")
  String subject;

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "value")
  String json;

  @Column(name = "expires_at")
  Instant expiresAt;

  /** The composite primary key. */
  public record Key(String namespace, String entryKey) implements Serializable {}

  /** For JPA. */
  protected EphemeralEntity() {}

  EphemeralEntity(String namespace, String entryKey, String owner, String subject, String json, Instant expiresAt) {
    this.namespace = namespace;
    this.entryKey = entryKey;
    this.owner = owner;
    this.subject = subject;
    this.json = json;
    this.expiresAt = expiresAt;
  }
}

package com.lattice.oidc.stores.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** A row of {@code passkeys}: one registered passkey. */
@Entity
@Table(name = "passkeys")
public class PasskeyEntity {

  @Id
  @Column(name = "id")
  String id;

  @Column(name = "subject")
  String subject;

  @Column(name = "user_handle")
  String userHandle;

  @Column(name = "public_key_cose")
  String publicKeyCose;

  @Column(name = "signature_count")
  long signatureCount;

  @Column(name = "name")
  String name;

  @Column(name = "created_at")
  Instant createdAt;

  @Column(name = "last_used_at")
  Instant lastUsedAt;

  @Column(name = "backed_up")
  boolean backedUp;

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "transports")
  String transports;

  /** For JPA. */
  protected PasskeyEntity() {}

  PasskeyEntity(String id, String subject, String userHandle, String publicKeyCose, long signatureCount, String name, Instant createdAt, Instant lastUsedAt, boolean backedUp, String transports) {
    this.id = id;
    this.subject = subject;
    this.userHandle = userHandle;
    this.publicKeyCose = publicKeyCose;
    this.signatureCount = signatureCount;
    this.name = name;
    this.createdAt = createdAt;
    this.lastUsedAt = lastUsedAt;
    this.backedUp = backedUp;
    this.transports = transports;
  }
}

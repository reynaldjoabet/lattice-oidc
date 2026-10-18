package com.lattice.oidc.stores.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.io.Serializable;

/** A row of {@code recovery_codes}: the hash of one unused recovery code. */
@Entity
@Table(name = "recovery_codes")
@IdClass(RecoveryCodeEntity.Key.class)
public class RecoveryCodeEntity {

  @Id
  @Column(name = "subject")
  String subject;

  @Id
  @Column(name = "code_hash")
  String codeHash;

  /** The composite primary key. */
  public record Key(String subject, String codeHash) implements Serializable {}

  /** For JPA. */
  protected RecoveryCodeEntity() {}

  RecoveryCodeEntity(String subject, String codeHash) {
    this.subject = subject;
    this.codeHash = codeHash;
  }
}

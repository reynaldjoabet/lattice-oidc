package com.lattice.oidc.stores.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** A row of {@code user_handles}: the WebAuthn user handle of an account. */
@Entity
@Table(name = "user_handles")
public class UserHandleEntity {

  @Id
  @Column(name = "subject")
  String subject;

  @Column(name = "handle")
  String handle;

  /** For JPA. */
  protected UserHandleEntity() {}

  UserHandleEntity(String subject, String handle) {
    this.subject = subject;
    this.handle = handle;
  }
}

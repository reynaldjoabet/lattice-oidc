package com.lattice.oidc.stores.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.io.Serializable;

/** A row of {@code session_clients}: an app signed in through a session. */
@Entity
@Table(name = "session_clients")
@IdClass(SessionClientEntity.Key.class)
public class SessionClientEntity {

  @Id
  @Column(name = "session_id")
  String sessionId;

  @Id
  @Column(name = "client_identifier")
  String clientIdentifier;

  /** The composite primary key. */
  public record Key(String sessionId, String clientIdentifier) implements Serializable {}

  /** For JPA. */
  protected SessionClientEntity() {}

  SessionClientEntity(String sessionId, String clientIdentifier) {
    this.sessionId = sessionId;
    this.clientIdentifier = clientIdentifier;
  }
}

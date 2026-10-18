package com.lattice.oidc.stores.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/** A row of {@code sessions}: a login session. */
@Entity
@Table(name = "sessions")
public class SessionEntity {

  @Id
  @Column(name = "id")
  String id;

  @Column(name = "subject")
  String subject;

  @Column(name = "user_agent")
  String userAgent;

  @Column(name = "ip")
  String ip;

  @Column(name = "method")
  String method;

  @Column(name = "created_at")
  Instant createdAt;

  @Column(name = "last_seen_at")
  Instant lastSeenAt;

  @Column(name = "expires_at")
  Instant expiresAt;

  @Column(name = "remember_me")
  boolean rememberMe;

  /** For JPA. */
  protected SessionEntity() {}

  SessionEntity(String id, String subject, String userAgent, String ip, String method, Instant createdAt, Instant lastSeenAt, Instant expiresAt, boolean rememberMe) {
    this.id = id;
    this.subject = subject;
    this.userAgent = userAgent;
    this.ip = ip;
    this.method = method;
    this.createdAt = createdAt;
    this.lastSeenAt = lastSeenAt;
    this.expiresAt = expiresAt;
    this.rememberMe = rememberMe;
  }
}

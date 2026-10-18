package com.lattice.oidc.stores.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** A row of {@code audit_events}: one audit record, as JSON, with its event and subject for filtering. */
@Entity
@Table(name = "audit_events")
public class AuditEventEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "id")
  Long id;

  @Column(name = "occurred_at")
  Instant occurredAt;

  @Column(name = "event")
  String event;

  @Column(name = "subject")
  String subject;

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "record")
  String recordJson;

  /** For JPA. */
  protected AuditEventEntity() {}

  AuditEventEntity(Instant occurredAt, String event, String subject, String recordJson) {
    this.occurredAt = occurredAt;
    this.event = event;
    this.subject = subject;
    this.recordJson = recordJson;
  }
}

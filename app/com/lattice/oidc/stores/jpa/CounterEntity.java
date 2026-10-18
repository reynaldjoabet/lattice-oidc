package com.lattice.oidc.stores.jpa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/** A row of {@code counters}: a rate-limit counter and the end of its window. */
@Entity
@Table(name = "counters")
public class CounterEntity {

  @Id
  @Column(name = "key")
  String counterKey;

  @Column(name = "count")
  long hits;

  @Column(name = "window_ends_at")
  Instant windowEndsAt;

  /** For JPA. */
  protected CounterEntity() {}

  CounterEntity(String counterKey, long hits, Instant windowEndsAt) {
    this.counterKey = counterKey;
    this.hits = hits;
    this.windowEndsAt = windowEndsAt;
  }
}

package com.lattice.oidc.stores;

import com.google.inject.ImplementedBy;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The stored audit trail, for the operator console's audit log. Records are the maps {@code
 * AuditService} builds (never containing secrets); the store adds an increasing {@code id}. With
 * PostgreSQL, records are kept for {@code lattice.audit.retention}.
 */
@ImplementedBy(InMemoryAuditEventStore.class)
public interface AuditEventStore {

  /** Which records to return: optional event name and subject, older than {@code beforeId}. */
  record Query(Optional<String> event, Optional<String> subject, Optional<Long> beforeId, int limit) {}

  void append(Map<String, Object> record);

  /** Matching records, newest first, each with its {@code id}. */
  List<Map<String, Object>> search(Query query);
}

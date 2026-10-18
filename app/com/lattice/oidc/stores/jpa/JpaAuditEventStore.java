package com.lattice.oidc.stores.jpa;

import com.lattice.oidc.common.JsonHelpers;
import com.lattice.oidc.stores.AuditEventStore;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.persistence.TypedQuery;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@link AuditEventStore} through JPA (entity {@link AuditEventEntity}, table {@code audit_events}).
 * The event name and subject have their own columns for filtering; the whole record is kept as JSON.
 */
@Singleton
public final class JpaAuditEventStore implements AuditEventStore {

  private final JpaDatabase database;

  @Inject
  public JpaAuditEventStore(JpaDatabase database) {
    this.database = database;
  }

  @Override
  public void append(Map<String, Object> record) {
    Object subject = record.containsKey("subject") ? record.get("subject") : record.get("login_id");
    database.transaction(
        em -> {
          em.persist(
              new AuditEventEntity(
                  Instant.parse(String.valueOf(record.get("ts"))),
                  String.valueOf(record.get("event")),
                  subject == null ? null : subject.toString(),
                  JsonHelpers.write(record)));
          return null;
        });
  }

  @Override
  public List<Map<String, Object>> search(Query query) {
    StringBuilder jpql = new StringBuilder("select a from AuditEventEntity a where true");
    query.event().ifPresent(event -> jpql.append(" and a.event = :event"));
    query.subject().ifPresent(subject -> jpql.append(" and a.subject = :subject"));
    query.beforeId().ifPresent(before -> jpql.append(" and a.id < :before"));
    jpql.append(" order by a.id desc");
    return database.transaction(
        em -> {
          TypedQuery<AuditEventEntity> search = em.createQuery(jpql.toString(), AuditEventEntity.class);
          query.event().ifPresent(event -> search.setParameter("event", event));
          query.subject().ifPresent(subject -> search.setParameter("subject", subject));
          query.beforeId().ifPresent(before -> search.setParameter("before", before));
          return search
              .setMaxResults(query.limit())
              .getResultStream()
              .map(
                  a -> {
                    Map<String, Object> record = new LinkedHashMap<>();
                    record.put("id", a.id);
                    record.putAll(JsonHelpers.readMap(a.recordJson));
                    return (Map<String, Object>) record;
                  })
              .toList();
        });
  }
}

package com.lattice.oidc.stores.postgres;

import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.stores.AuditEventStore;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.inject.Inject;
import javax.inject.Singleton;

/**
 * {@link AuditEventStore} in PostgreSQL (table {@code audit_events}). The event name and subject
 * have their own columns for filtering; the whole record is kept as JSON.
 */
@Singleton
public final class PostgresAuditEventStore implements AuditEventStore {

  private final PostgresDatabase database;

  @Inject
  public PostgresAuditEventStore(PostgresDatabase database) {
    this.database = database;
  }

  @Override
  public void append(Map<String, Object> record) {
    Object subject = record.containsKey("subject") ? record.get("subject") : record.get("login_id");
    database.update(
        "INSERT INTO audit_events (occurred_at, event, subject, record) VALUES (?, ?, ?, ?::jsonb)",
        Instant.parse(String.valueOf(record.get("ts"))),
        String.valueOf(record.get("event")),
        subject == null ? null : subject.toString(),
        Jsons.write(record));
  }

  @Override
  public List<Map<String, Object>> search(Query query) {
    StringBuilder sql = new StringBuilder("SELECT id, record::text AS record FROM audit_events WHERE true");
    List<Object> parameters = new ArrayList<>();
    query.event().ifPresent(event -> {
      sql.append(" AND event = ?");
      parameters.add(event);
    });
    query.subject().ifPresent(subject -> {
      sql.append(" AND subject = ?");
      parameters.add(subject);
    });
    query.beforeId().ifPresent(before -> {
      sql.append(" AND id < ?");
      parameters.add(before);
    });
    sql.append(" ORDER BY id DESC LIMIT ?");
    parameters.add(query.limit());
    return database.query(
        sql.toString(),
        row -> {
          Map<String, Object> record = new LinkedHashMap<>();
          record.put("id", row.getLong("id"));
          record.putAll(Jsons.readMap(row.getString("record")));
          return record;
        },
        parameters.toArray());
  }
}

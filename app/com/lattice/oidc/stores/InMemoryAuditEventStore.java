package com.lattice.oidc.stores;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import javax.inject.Singleton;

/** {@link AuditEventStore} in memory, for one server: the latest {@link #CAPACITY} records. */
@Singleton
public final class InMemoryAuditEventStore implements AuditEventStore {

  static final int CAPACITY = 10_000;

  private final Deque<Map<String, Object>> records = new ArrayDeque<>();
  private final AtomicLong ids = new AtomicLong();

  @Override
  public void append(Map<String, Object> record) {
    Map<String, Object> stored = new LinkedHashMap<>();
    stored.put("id", ids.incrementAndGet());
    stored.putAll(record);
    synchronized (records) {
      records.addFirst(java.util.Collections.unmodifiableMap(stored));
      while (records.size() > CAPACITY) {
        records.removeLast();
      }
    }
  }

  @Override
  public List<Map<String, Object>> search(Query query) {
    synchronized (records) {
      return records.stream()
          .filter(record -> query.event().map(event -> event.equals(record.get("event"))).orElse(true))
          .filter(record -> query.subject().map(subject -> Objects.equals(subject, record.get("subject"))).orElse(true))
          .filter(record -> query.beforeId().map(before -> ((Long) record.get("id")) < before).orElse(true))
          .limit(query.limit())
          .toList();
    }
  }
}

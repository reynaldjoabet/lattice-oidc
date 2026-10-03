package com.lattice.oidc.security;

import com.google.inject.ImplementedBy;
import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.filters.RequestIdFilter;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.mvc.Http;

/**
 * Audit trail of security-relevant events (authentication, consent, logout, client changes),
 * written as one JSON object per line to a pluggable {@link Sink} — by default the {@code audit}
 * logger, which can be routed to a SIEM through logback. Events never contain passwords, tokens or
 * other secrets.
 */
@Singleton
public final class AuditService {

  /** Security events. */
  public enum Event {
    LOGIN_SUCCEEDED,
    LOGIN_FAILED,
    LOGIN_LOCKED,
    FEDERATED_LOGIN,
    FEDERATED_LOGIN_FAILED,
    CONSENT_GRANTED,
    CONSENT_DENIED,
    DEVICE_AUTHORIZED,
    DEVICE_DENIED,
    LOGOUT,
    CLIENT_REGISTERED,
    CLIENT_UPDATED,
    CLIENT_DELETED
  }

  /** Destination of audit records. */
  @ImplementedBy(LogSink.class)
  public interface Sink {
    void write(Map<String, Object> record);
  }

  /** Writes audit records as JSON lines to the {@code audit} logger. */
  @Singleton
  public static final class LogSink implements Sink {
    private static final Logger AUDIT = LoggerFactory.getLogger("audit");

    @Override
    public void write(Map<String, Object> record) {
      AUDIT.info(Jsons.write(record));
    }
  }

  private final Sink sink;

  @Inject
  public AuditService(Sink sink) {
    this.sink = sink;
  }

  /**
   * Records an event.
   *
   * @param request the request that triggered the event (for request id and client address)
   * @param event what happened
   * @param details event-specific, non-secret attributes (e.g. subject, client_id); null values
   *     are skipped
   */
  public void record(Http.RequestHeader request, Event event, Object... details) {
    Map<String, Object> record = new LinkedHashMap<>();
    record.put("ts", Instant.now().toString());
    record.put("event", event.name());
    record.put("request_id", RequestIdFilter.of(request));
    record.put("ip", request.remoteAddress());
    for (int i = 0; i + 1 < details.length; i += 2) {
      if (details[i + 1] != null) {
        record.put(String.valueOf(details[i]), details[i + 1]);
      }
    }
    sink.write(record);
  }
}

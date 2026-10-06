package com.lattice.oidc.security;

import com.google.inject.ImplementedBy;
import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.filters.RequestIdFilter;
import com.lattice.oidc.metrics.Metrics;
import com.lattice.oidc.stores.AuditEventStore;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
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
    /** Signed in; {@code method} says how (password, password + totp, passkey, ...). */
    LOGIN_SUCCEEDED,
    /** A wrong password or passkey; a wrong second factor is {@link #SECOND_FACTOR_FAILED}. */
    LOGIN_FAILED,
    LOGIN_LOCKED,
    /** The password was right; the sign-in waits for the second factor ({@code factor}). */
    SECOND_FACTOR_REQUIRED,
    /** A wrong second factor; {@code factor} is totp or recovery_code. */
    SECOND_FACTOR_FAILED,
    /** A signed-in user confirmed their password before a sensitive change. */
    PASSWORD_CONFIRMED,
    BROKERED_LOGIN,
    BROKERED_LOGIN_FAILED,
    ACCOUNT_LINKED,
    CONSENT_GRANTED,
    /** Issued without the consent page: the account had already approved everything requested. */
    CONSENT_REUSED,
    CONSENT_DENIED,
    DEVICE_AUTHORIZED,
    DEVICE_DENIED,
    LOGOUT,
    CLIENT_REGISTERED,
    CLIENT_UPDATED,
    CLIENT_DELETED,
    APP_ACCESS_REMOVED,
    CIBA_APPROVED,
    CIBA_DENIED,
    PASSKEY_ADDED,
    PASSKEY_REMOVED,
    STEP_UP,
    SESSION_ENDED,
    SIGN_IN_REPORTED,
    PASSWORD_RESET_REQUESTED,
    PASSWORD_CHANGED,
    CLIENT_SECRET_ROTATED,
    SECOND_FACTOR_ADDED,
    SECOND_FACTOR_REMOVED,
    RECOVERY_CODE_USED,
    RECOVERY_CODES_REPLACED,
    EMAIL_VERIFIED,
    TERMS_ACCEPTED,
    TERMS_DECLINED
  }

  /** How many recent events the operator console overview shows. */
  public static final int RECENT_LIMIT = 50;

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

  private static final Logger LOG = LoggerFactory.getLogger(AuditService.class);

  private final Sink sink;
  private final SecurityStats stats;
  private final Metrics metrics;
  private final AuditEventStore store;
  private final Webhooks webhooks;

  @Inject
  public AuditService(Sink sink, SecurityStats stats, Metrics metrics, AuditEventStore store, Webhooks webhooks) {
    this.sink = sink;
    this.stats = stats;
    this.metrics = metrics;
    this.store = store;
    this.webhooks = webhooks;
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
    stats.observe(event, request.remoteAddress(), record.get("login_id"));
    metrics.auditEvent(event.name());
    try {
      store.append(record);
    } catch (RuntimeException e) {
      // The log line above is the record of last resort; storage trouble never fails the request.
      LOG.warn("Could not store audit event {}: {}", event, e.getMessage());
    }
    if (webhooks.enabled()) {
      webhooks.deliver(record);
    }
  }

  /** The most recent events, newest first (for the operator console). */
  public java.util.List<Map<String, Object>> recent() {
    return search(new AuditEventStore.Query(java.util.Optional.empty(), java.util.Optional.empty(), java.util.Optional.empty(), RECENT_LIMIT));
  }

  /** Stored events matching the query, newest first (the console's audit log). */
  public java.util.List<Map<String, Object>> search(AuditEventStore.Query query) {
    return store.search(query);
  }
}

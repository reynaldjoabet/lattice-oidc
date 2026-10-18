package com.lattice.oidc.stores.postgres;

import static com.lattice.oidc.stores.postgres.PostgresApp.unique;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.lattice.oidc.models.Consent;
import com.lattice.oidc.stores.AuditEventStore;
import com.lattice.oidc.stores.AuditEventStore.Query;
import com.lattice.oidc.stores.ConsentStore;
import com.lattice.oidc.stores.EphemeralStore;
import com.lattice.oidc.stores.SessionStore;
import com.lattice.oidc.stores.SessionStore.Session;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import play.Application;
import play.test.Helpers;

/** Open Banking consents, the audit trail and the expiry cleanup in PostgreSQL. */
public class PostgresRecordStoresTest {

  private static Application app;

  @BeforeClass
  public static void start() {
    app = PostgresApp.start();
  }

  @AfterClass
  public static void stop() {
    Helpers.stop(app);
  }

  // ---------------------------------------------------------------- Open Banking consents

  private static Consent consent(String id, String status) {
    return new Consent(id, List.of("ACCOUNTS_READ", "RESOURCES_READ"), status, "2026-01-01T00:00:00Z",
        Instant.now().plus(Duration.ofDays(30)).toString(), "2026-01-01T00:00:00Z", 42, null);
  }

  @Test
  public void anOpenBankingConsentReadsBackIsReplacedAndDeleted() {
    ConsentStore consents = app.injector().instanceOf(ConsentStore.class);
    String id = unique("urn:consent");
    Consent awaiting = consent(id, "AWAITING_AUTHORISATION");
    consents.save(awaiting);
    assertEquals(Optional.of(awaiting), consents.find(id));
    Consent authorised = consent(id, "AUTHORISED");
    consents.save(authorised);
    assertEquals(Optional.of(authorised), consents.find(id));
    consents.delete(id);
    assertEquals(Optional.empty(), consents.find(id));
    assertEquals(Optional.empty(), consents.find(null));
  }

  // ----------------------------------------------------------------------- audit events

  private static Map<String, Object> event(String event, String key, String value) {
    Map<String, Object> record = new LinkedHashMap<>();
    record.put("ts", Instant.now().toString());
    record.put("event", event);
    record.put(key, value);
    record.put("ip", "203.0.113.7");
    return record;
  }

  @Test
  public void auditEventsAreSearchedByEventAndSubjectNewestFirst() {
    AuditEventStore audit = app.injector().instanceOf(AuditEventStore.class);
    String subject = unique("user");
    String loginId = unique("login");
    audit.append(event("LOGIN_SUCCEEDED", "subject", subject));
    audit.append(event("LOGIN_FAILED", "login_id", loginId));
    audit.append(event("LOGOUT", "subject", subject));

    List<Map<String, Object>> mine =
        audit.search(new Query(Optional.empty(), Optional.of(subject), Optional.empty(), 10));
    assertEquals(List.of("LOGOUT", "LOGIN_SUCCEEDED"), mine.stream().map(r -> r.get("event")).toList());
    assertEquals("203.0.113.7", mine.get(0).get("ip"));
    assertTrue("each record carries its id", mine.get(0).get("id") instanceof Long);

    List<Map<String, Object>> failed =
        audit.search(new Query(Optional.of("LOGIN_FAILED"), Optional.of(loginId), Optional.empty(), 10));
    assertEquals("without a subject, the login ID is the subject", 1, failed.size());
  }

  @Test
  public void auditEventsArePagedByIdAndLimit() {
    AuditEventStore audit = app.injector().instanceOf(AuditEventStore.class);
    String subject = unique("user");
    for (int i = 0; i < 5; i++) {
      audit.append(event("STEP_" + i, "subject", subject));
    }
    List<Map<String, Object>> first = audit.search(new Query(Optional.empty(), Optional.of(subject), Optional.empty(), 2));
    assertEquals(List.of("STEP_4", "STEP_3"), first.stream().map(r -> r.get("event")).toList());
    long before = (Long) first.get(1).get("id");
    List<Map<String, Object>> next =
        audit.search(new Query(Optional.empty(), Optional.of(subject), Optional.of(before), 2));
    assertEquals(List.of("STEP_2", "STEP_1"), next.stream().map(r -> r.get("event")).toList());
  }

  // -------------------------------------------------------------------------- cleanup

  @Test
  public void theCleanupDeletesOnlyExpiredRows() throws Exception {
    EphemeralStore entries = app.injector().instanceOf(EphemeralStore.class);
    SessionStore sessions = app.injector().instanceOf(SessionStore.class);
    String ns = unique("ns");
    entries.put(ns, "expired", null, null, "{}", Duration.ofMillis(50));
    entries.put(ns, "live", null, null, "{}", Duration.ofMinutes(5));
    Instant now = PostgresApp.now();
    String expiredSession = unique("s");
    sessions.create(new Session(expiredSession, "u", null, null, "password", now, now, now.minus(Duration.ofSeconds(1)), false));
    String liveSession = unique("s");
    sessions.create(new Session(liveSession, "u", null, null, "password", now, now, now.plus(Duration.ofHours(1)), false));
    Thread.sleep(150);

    long entriesBefore = PostgresApp.rows(app, "ephemeral");
    long sessionsBefore = PostgresApp.rows(app, "sessions");
    app.injector().instanceOf(StorageCleanup.class).run();

    assertTrue("the expired entry was deleted", PostgresApp.rows(app, "ephemeral") < entriesBefore);
    assertTrue("the expired session was deleted", PostgresApp.rows(app, "sessions") < sessionsBefore);
    assertTrue(entries.get(ns, "live").isPresent());
    assertTrue(sessions.find(liveSession).isPresent());
  }
}

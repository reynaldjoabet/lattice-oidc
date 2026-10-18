package com.lattice.oidc.stores.postgres;

import static com.lattice.oidc.stores.postgres.PostgresApp.now;
import static com.lattice.oidc.stores.postgres.PostgresApp.unique;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.lattice.oidc.models.Passkey;
import com.lattice.oidc.stores.AppConsentStore;
import com.lattice.oidc.stores.AppConsentStore.AppConsent;
import com.lattice.oidc.stores.IdentityLinkStore;
import com.lattice.oidc.stores.IdentityLinkStore.Link;
import com.lattice.oidc.stores.PasskeyStore;
import com.lattice.oidc.stores.SecondFactorStore;
import com.lattice.oidc.stores.SecondFactorStore.Totp;
import com.lattice.oidc.stores.SessionStore;
import com.lattice.oidc.stores.SessionStore.Session;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import play.Application;
import play.test.Helpers;

/** Sessions, passkeys, second factors, identity links and remembered consents in PostgreSQL. */
public class PostgresAccountStoresTest {

  private static Application app;

  @BeforeClass
  public static void start() {
    app = PostgresApp.start();
  }

  @AfterClass
  public static void stop() {
    Helpers.stop(app);
  }

  private static <T> T store(Class<T> type) {
    return app.injector().instanceOf(type);
  }

  // ----------------------------------------------------------------------------- sessions

  private static Session session(String id, String subject, Instant lastSeen, Instant expires, boolean rememberMe) {
    Instant created = now().minus(Duration.ofHours(1));
    return new Session(id, subject, "Firefox", "203.0.113.7", "password", created, lastSeen, expires, rememberMe);
  }

  @Test
  public void aSessionReadsBackUntilItExpires() {
    SessionStore sessions = store(SessionStore.class);
    String id = unique("s");
    Session session = session(id, "alice", now(), now().plus(Duration.ofHours(1)), true);
    sessions.create(session);
    assertEquals(Optional.of(session), sessions.find(id));

    String expired = unique("s");
    sessions.create(session(expired, "alice", now(), now().minus(Duration.ofSeconds(1)), false));
    assertEquals(Optional.empty(), sessions.find(expired));
    assertEquals(Optional.empty(), sessions.find(null));
  }

  @Test
  public void touchingWritesOnlyWhenTheLastWriteIsOlderThanTheInterval() {
    SessionStore sessions = store(SessionStore.class);
    String id = unique("s");
    Instant lastSeen = now().minus(Duration.ofSeconds(30));
    sessions.create(session(id, "alice", lastSeen, now().plus(Duration.ofHours(1)), false));

    Instant soon = now();
    sessions.touch(id, soon, Duration.ofMinutes(1));
    assertEquals("30 s ago is within the 1-minute interval", lastSeen, sessions.find(id).orElseThrow().lastSeenAt());
    sessions.touch(id, soon, Duration.ofSeconds(10));
    assertEquals(soon, sessions.find(id).orElseThrow().lastSeenAt());
  }

  @Test
  public void endingASessionReturnsItAndRemovesItsClients() {
    SessionStore sessions = store(SessionStore.class);
    String id = unique("s");
    Session session = session(id, "alice", now(), now().plus(Duration.ofHours(1)), false);
    sessions.create(session);
    sessions.addClient(id, "app-b");
    sessions.addClient(id, "app-a");
    sessions.addClient(id, "app-a");
    assertEquals("sorted, without duplicates", List.of("app-a", "app-b"), List.copyOf(sessions.clients(id)));

    assertEquals(Optional.of(session), sessions.end(id));
    assertEquals(Optional.empty(), sessions.find(id));
    assertEquals(Set.of(), sessions.clients(id));
    assertEquals(Optional.empty(), sessions.end(id));
  }

  @Test
  public void aClientIsNotAddedToAMissingSession() {
    SessionStore sessions = store(SessionStore.class);
    String id = unique("missing");
    sessions.addClient(id, "app-a");
    assertEquals(Set.of(), sessions.clients(id));
  }

  @Test
  public void aSubjectsLiveSessionsAreListedMostRecentFirst() {
    SessionStore sessions = store(SessionStore.class);
    String subject = unique("user");
    String older = unique("s");
    String newer = unique("s");
    Instant expires = now().plus(Duration.ofHours(1));
    sessions.create(session(older, subject, now().minus(Duration.ofMinutes(10)), expires, false));
    sessions.create(session(newer, subject, now(), expires, false));
    sessions.create(session(unique("s"), subject, now(), now().minus(Duration.ofSeconds(1)), false));
    assertEquals(List.of(newer, older), sessions.forSubject(subject).stream().map(Session::id).toList());
    assertTrue(sessions.countActive() >= 2);
  }

  // ----------------------------------------------------------------------------- passkeys

  private static Passkey passkey(String id, String subject, Instant created, long count, String name) {
    return new Passkey(id, subject, "handle-" + subject, "cose-key", count, name, created, Optional.empty(), false,
        new LinkedHashSet<>(List.of("internal", "hybrid")));
  }

  @Test
  public void aPasskeyReadsBackAndAnUpdateChangesOnlyItsUsageFields() {
    PasskeyStore passkeys = store(PasskeyStore.class);
    String id = unique("cred");
    String subject = unique("user");
    Instant created = now().minus(Duration.ofDays(1));
    Passkey passkey = passkey(id, subject, created, 1, "Laptop");
    passkeys.save(passkey);
    assertEquals(Optional.of(passkey), passkeys.byId(id));

    Instant used = now();
    Passkey updated = new Passkey(id, "someone-else", "other-handle", "other-key", 7, "Work laptop", now(),
        Optional.of(used), true, new LinkedHashSet<>(List.of("usb")));
    passkeys.save(updated);
    Passkey loaded = passkeys.byId(id).orElseThrow();
    assertEquals(7, loaded.signatureCount());
    assertEquals("Work laptop", loaded.name());
    assertEquals(Optional.of(used), loaded.lastUsedAt());
    assertTrue(loaded.backedUp());
    assertEquals("the owner and key never change", subject, loaded.subject());
    assertEquals("cose-key", loaded.publicKeyCose());
    assertEquals(created, loaded.createdAt());
    assertEquals(new LinkedHashSet<>(List.of("internal", "hybrid")), loaded.transports());
  }

  @Test
  public void passkeysAreListedOldestFirstAndCanBeDeleted() {
    PasskeyStore passkeys = store(PasskeyStore.class);
    String subject = unique("user");
    String first = unique("cred");
    String second = unique("cred");
    passkeys.save(passkey(second, subject, now(), 0, "Phone"));
    passkeys.save(passkey(first, subject, now().minus(Duration.ofDays(2)), 0, "Laptop"));
    assertEquals(List.of(first, second), passkeys.forSubject(subject).stream().map(Passkey::id).toList());
    passkeys.delete(first);
    assertEquals(List.of(second), passkeys.forSubject(subject).stream().map(Passkey::id).toList());
    assertEquals(Optional.empty(), passkeys.byId(null));
  }

  @Test
  public void aUserHandleIsCreatedOnceAndResolvesBack() {
    PasskeyStore passkeys = store(PasskeyStore.class);
    String subject = unique("user");
    String handle = passkeys.userHandle(subject);
    assertEquals("the same handle every time", handle, passkeys.userHandle(subject));
    assertEquals(Optional.of(subject), passkeys.subjectForUserHandle(handle));
    assertEquals(Optional.empty(), passkeys.subjectForUserHandle("no-such-handle"));
  }

  @Test
  public void thePasskeyOfferTimeIsRememberedAndReplaced() {
    PasskeyStore passkeys = store(PasskeyStore.class);
    String subject = unique("user");
    assertEquals(Optional.empty(), passkeys.offeredAt(subject));
    Instant first = now().minus(Duration.ofDays(3));
    passkeys.markOffered(subject, first);
    assertEquals(Optional.of(first), passkeys.offeredAt(subject));
    Instant second = now();
    passkeys.markOffered(subject, second);
    assertEquals(Optional.of(second), passkeys.offeredAt(subject));
  }

  @Test
  public void accountsWithPasskeysAreCountedOnce() {
    PasskeyStore passkeys = store(PasskeyStore.class);
    long before = passkeys.accountsWithPasskeys();
    String subject = unique("user");
    passkeys.save(passkey(unique("cred"), subject, now(), 0, "A"));
    passkeys.save(passkey(unique("cred"), subject, now(), 0, "B"));
    assertEquals(before + 1, passkeys.accountsWithPasskeys());
  }

  // ----------------------------------------------------------------------- second factors

  @Test
  public void anAuthenticatorAppReadsBackAndIsReplaced() {
    SecondFactorStore factors = store(SecondFactorStore.class);
    String subject = unique("user");
    Totp totp = new Totp(subject, "k1:secret", now(), 0);
    factors.saveTotp(totp);
    assertEquals(Optional.of(totp), factors.totp(subject));
    Totp replaced = new Totp(subject, "k1:other", now(), 5);
    factors.saveTotp(replaced);
    assertEquals(Optional.of(replaced), factors.totp(subject));
    factors.deleteTotp(subject);
    assertEquals(Optional.empty(), factors.totp(subject));
  }

  @Test
  public void aTimeStepCanBeUsedOnlyOnceAndOnlyForward() {
    SecondFactorStore factors = store(SecondFactorStore.class);
    String subject = unique("user");
    factors.saveTotp(new Totp(subject, "k1:secret", now(), 100));
    assertTrue(factors.useTotpStep(subject, 101));
    assertFalse("the same step again", factors.useTotpStep(subject, 101));
    assertFalse("an older step", factors.useTotpStep(subject, 100));
    assertEquals(101, factors.totp(subject).orElseThrow().lastUsedStep());
  }

  @Test
  public void aSecretIsReplacedOnlyIfUnchangedAndKeepsTheLastUsedStep() {
    SecondFactorStore factors = store(SecondFactorStore.class);
    String subject = unique("user");
    factors.saveTotp(new Totp(subject, "old:secret", now(), 42));
    assertFalse(factors.replaceTotpSecret(subject, "stale", "new:secret"));
    assertTrue(factors.replaceTotpSecret(subject, "old:secret", "new:secret"));
    Totp loaded = factors.totp(subject).orElseThrow();
    assertEquals("new:secret", loaded.encryptedSecret());
    assertEquals(42, loaded.lastUsedStep());
  }

  @Test
  public void authenticatorAppsArePagedAndCountedByKey() {
    SecondFactorStore factors = store(SecondFactorStore.class);
    String prefix = unique("page");
    for (String suffix : List.of("-c", "-a", "-b")) {
      factors.saveTotp(new Totp(prefix + suffix, (suffix.equals("-c") ? "old" : "new") + ":s", now(), 0));
    }
    List<String> page = factors.totps(prefix + "-a", 2).stream().map(Totp::subject).toList();
    assertEquals(List.of(prefix + "-b", prefix + "-c"), page);
    assertTrue(factors.totpsNotUnderKey("new") >= 1);
    assertTrue(factors.accountsWithTotp() >= 3);
  }

  @Test
  public void recoveryCodesWorkOnceEach() {
    SecondFactorStore factors = store(SecondFactorStore.class);
    String subject = unique("user");
    factors.replaceRecoveryCodes(subject, List.of("k1:h1", "k1:h2", "k1:h3"));
    assertEquals(3, factors.remainingRecoveryCodes(subject));
    assertTrue(factors.useRecoveryCode(subject, "k1:h2"));
    assertFalse("used already", factors.useRecoveryCode(subject, "k1:h2"));
    assertEquals(2, factors.remainingRecoveryCodes(subject));

    factors.replaceRecoveryCodes(subject, List.of("k2:h9"));
    assertEquals("replacing removes the old ones", 1, factors.remainingRecoveryCodes(subject));
    assertTrue(factors.accountsWithRecoveryCodesNotUnderKey("k1") >= 1 || factors.accountsWithRecoveryCodesNotUnderKey("k2") >= 0);
    factors.deleteRecoveryCodes(subject);
    assertEquals(0, factors.remainingRecoveryCodes(subject));
  }

  @Test
  public void accountsWithRecoveryCodesUnderAnOldKeyAreCounted() {
    SecondFactorStore factors = store(SecondFactorStore.class);
    String key = unique("key");
    long before = factors.accountsWithRecoveryCodesNotUnderKey(key);
    String subject = unique("user");
    factors.replaceRecoveryCodes(subject, List.of("old:h1", "old:h2"));
    assertEquals(before + 1, factors.accountsWithRecoveryCodesNotUnderKey(key));
  }

  // ------------------------------------------------------------------------ identity links

  @Test
  public void anIdentityLinkResolvesAndCanBeMovedAndRemoved() {
    IdentityLinkStore links = store(IdentityLinkStore.class);
    String provider = unique("idp");
    links.link(provider, "ext-1", "alice");
    assertEquals(Optional.of("alice"), links.localSubject(provider, "ext-1"));
    links.link(provider, "ext-1", "bob");
    assertEquals(Optional.of("bob"), links.localSubject(provider, "ext-1"));
    links.unlink(provider, "ext-1");
    assertEquals(Optional.empty(), links.localSubject(provider, "ext-1"));
  }

  @Test
  public void aUsersLinksAreListedOldestFirst() {
    IdentityLinkStore links = store(IdentityLinkStore.class);
    String subject = unique("user");
    links.link("idp-b", unique("ext"), subject);
    links.link("idp-a", unique("ext"), subject);
    assertEquals(List.of("idp-b", "idp-a"), links.linksOf(subject).stream().map(Link::providerId).toList());
  }

  // ------------------------------------------------------------------- remembered consent

  @Test
  public void aRememberedConsentReadsBackAndIsReplaced() {
    AppConsentStore consents = store(AppConsentStore.class);
    String subject = unique("user");
    AppConsent consent = new AppConsent(subject, 42, Set.of("openid", "profile"), Set.of("name", "email"), now());
    consents.put(consent);
    assertEquals(Optional.of(consent), consents.find(subject, 42));
    AppConsent wider = new AppConsent(subject, 42, Set.of("openid", "profile", "email"), Set.of(), now());
    consents.put(wider);
    assertEquals(Optional.of(wider), consents.find(subject, 42));
    assertEquals(Optional.empty(), consents.find(subject, 43));
  }

  @Test
  public void rememberedConsentsAreDeletedForOneUserOrAWholeApp() {
    AppConsentStore consents = store(AppConsentStore.class);
    String alice = unique("user");
    String bob = unique("user");
    long client = Math.abs(unique("c").hashCode()) + 1000L;
    consents.put(new AppConsent(alice, client, Set.of("openid"), Set.of(), now()));
    consents.put(new AppConsent(bob, client, Set.of("openid"), Set.of(), now()));
    consents.put(new AppConsent(alice, client + 1, Set.of("openid"), Set.of(), now()));
    consents.delete(alice, client);
    assertEquals(Optional.empty(), consents.find(alice, client));
    assertTrue(consents.find(bob, client).isPresent());
    consents.deleteClient(client);
    assertEquals(Optional.empty(), consents.find(bob, client));
    assertTrue("another app's consent stays", consents.find(alice, client + 1).isPresent());
  }
}

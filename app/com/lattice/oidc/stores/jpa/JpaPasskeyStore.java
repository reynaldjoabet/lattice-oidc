package com.lattice.oidc.stores.jpa;

import com.lattice.oidc.common.JsonHelpers;
import com.lattice.oidc.models.Passkey;
import com.lattice.oidc.stores.PasskeyStore;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;

/**
 * {@link PasskeyStore} through JPA (entities {@link PasskeyEntity}, {@link UserHandleEntity} and
 * {@link PasskeyOfferEntity}; tables {@code passkeys}, {@code user_handles}, {@code passkey_offers}).
 */
@Singleton
public final class JpaPasskeyStore implements PasskeyStore {

  private static final SecureRandom RANDOM = new SecureRandom();

  private final JpaDatabase database;

  @Inject
  public JpaPasskeyStore(JpaDatabase database) {
    this.database = database;
  }

  private static Passkey passkey(PasskeyEntity p) {
    LinkedHashSet<String> transports = new LinkedHashSet<>();
    JsonHelpers.readList(p.transports).forEach(transport -> transports.add(String.valueOf(transport)));
    return new Passkey(p.id, p.subject, p.userHandle, p.publicKeyCose, p.signatureCount, p.name, p.createdAt,
        Optional.ofNullable(p.lastUsedAt), p.backedUp, transports);
  }

  @Override
  public List<Passkey> forSubject(String subject) {
    return database.transaction(
        em ->
            em.createQuery("select p from PasskeyEntity p where p.subject = :subject order by p.createdAt", PasskeyEntity.class)
                .setParameter("subject", subject)
                .getResultStream()
                .map(JpaPasskeyStore::passkey)
                .toList());
  }

  @Override
  public Optional<Passkey> byId(String credentialId) {
    if (credentialId == null) {
      return Optional.empty();
    }
    return database.transaction(
        em -> Optional.ofNullable(em.find(PasskeyEntity.class, credentialId)).map(JpaPasskeyStore::passkey));
  }

  @Override
  public void save(Passkey passkey) {
    // Native SQL: an atomic upsert that updates only the usage fields. The owner, handle, key,
    // creation time and transports of an existing passkey never change.
    database.transaction(
        em ->
            em.createNativeQuery(
                    """
                    INSERT INTO passkeys (id, subject, user_handle, public_key_cose, signature_count, name, created_at,
                                          last_used_at, backed_up, transports)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, CAST(?8 AS timestamptz), ?9, CAST(?10 AS jsonb))
                    ON CONFLICT (id) DO UPDATE SET
                      signature_count = EXCLUDED.signature_count, name = EXCLUDED.name,
                      last_used_at = EXCLUDED.last_used_at, backed_up = EXCLUDED.backed_up
                    """)
                .setParameter(1, passkey.id())
                .setParameter(2, passkey.subject())
                .setParameter(3, passkey.userHandle())
                .setParameter(4, passkey.publicKeyCose())
                .setParameter(5, passkey.signatureCount())
                .setParameter(6, passkey.name())
                .setParameter(7, passkey.createdAt())
                .setParameter(8, passkey.lastUsedAt().orElse(null))
                .setParameter(9, passkey.backedUp())
                .setParameter(10, JsonHelpers.write(passkey.transports()))
                .executeUpdate());
  }

  @Override
  public void delete(String credentialId) {
    database.transaction(
        em -> em.createQuery("delete from PasskeyEntity p where p.id = :id").setParameter("id", credentialId).executeUpdate());
  }

  @Override
  public String userHandle(String subject) {
    byte[] bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    String candidate = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    // Native SQL: keeps the existing handle if another request (on any server) created one first.
    return database.transaction(
        em -> {
          em.createNativeQuery("INSERT INTO user_handles (subject, handle) VALUES (?1, ?2) ON CONFLICT (subject) DO NOTHING")
              .setParameter(1, subject)
              .setParameter(2, candidate)
              .executeUpdate();
          return em.createQuery("select h.handle from UserHandleEntity h where h.subject = :subject", String.class)
              .setParameter("subject", subject)
              .getSingleResult();
        });
  }

  @Override
  public Optional<String> subjectForUserHandle(String userHandle) {
    return database.transaction(
        em ->
            em.createQuery("select h.subject from UserHandleEntity h where h.handle = :handle", String.class)
                .setParameter("handle", userHandle)
                .getResultStream()
                .findFirst());
  }

  @Override
  public Optional<Instant> offeredAt(String subject) {
    return database.transaction(
        em -> Optional.ofNullable(em.find(PasskeyOfferEntity.class, subject)).map(offer -> offer.offeredAt));
  }

  @Override
  public void markOffered(String subject, Instant at) {
    database.transaction(
        em ->
            em.createNativeQuery(
                    """
                    INSERT INTO passkey_offers (subject, offered_at) VALUES (?1, ?2)
                    ON CONFLICT (subject) DO UPDATE SET offered_at = EXCLUDED.offered_at
                    """)
                .setParameter(1, subject)
                .setParameter(2, at)
                .executeUpdate());
  }

  @Override
  public long accountsWithPasskeys() {
    return database.transaction(
        em -> em.createQuery("select count(distinct p.subject) from PasskeyEntity p", Long.class).getSingleResult());
  }
}

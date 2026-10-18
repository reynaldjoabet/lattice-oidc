package com.lattice.oidc.stores.jpa;

import com.lattice.oidc.stores.SecondFactorStore;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.List;
import java.util.Optional;

/**
 * {@link SecondFactorStore} through JPA (entities {@link TotpEntity} and {@link RecoveryCodeEntity};
 * tables {@code totp_credentials} and {@code recovery_codes}).
 */
@Singleton
public final class JpaSecondFactorStore implements SecondFactorStore {

  private final JpaDatabase database;

  @Inject
  public JpaSecondFactorStore(JpaDatabase database) {
    this.database = database;
  }

  private static Totp totp(TotpEntity t) {
    return new Totp(t.subject, t.secret, t.createdAt, t.lastUsedStep);
  }

  @Override
  public Optional<Totp> totp(String subject) {
    return database.transaction(em -> Optional.ofNullable(em.find(TotpEntity.class, subject)).map(JpaSecondFactorStore::totp));
  }

  @Override
  public void saveTotp(Totp totp) {
    // Native SQL: an atomic upsert.
    database.transaction(
        em ->
            em.createNativeQuery(
                    """
                    INSERT INTO totp_credentials (subject, secret, created_at, last_used_step) VALUES (?1, ?2, ?3, ?4)
                    ON CONFLICT (subject) DO UPDATE SET
                      secret = EXCLUDED.secret, created_at = EXCLUDED.created_at, last_used_step = EXCLUDED.last_used_step
                    """)
                .setParameter(1, totp.subject())
                .setParameter(2, totp.encryptedSecret())
                .setParameter(3, totp.createdAt())
                .setParameter(4, totp.lastUsedStep())
                .executeUpdate());
  }

  @Override
  public void deleteTotp(String subject) {
    database.transaction(
        em -> em.createQuery("delete from TotpEntity t where t.subject = :subject").setParameter("subject", subject).executeUpdate());
  }

  @Override
  public boolean replaceTotpSecret(String subject, String expected, String replacement) {
    // One bulk update, only the secret: a code used meanwhile keeps its last_used_step.
    return database.transaction(
            em ->
                em.createQuery("update TotpEntity t set t.secret = :replacement where t.subject = :subject and t.secret = :expected")
                    .setParameter("replacement", replacement)
                    .setParameter("subject", subject)
                    .setParameter("expected", expected)
                    .executeUpdate())
        == 1;
  }

  @Override
  public List<Totp> totps(String afterSubject, int limit) {
    return database.transaction(
        em ->
            em.createQuery("select t from TotpEntity t where t.subject > :after order by t.subject", TotpEntity.class)
                .setParameter("after", afterSubject == null ? "" : afterSubject)
                .setMaxResults(limit)
                .getResultStream()
                .map(JpaSecondFactorStore::totp)
                .toList());
  }

  @Override
  public long totpsNotUnderKey(String keyId) {
    return database.transaction(
        em ->
            em.createQuery("select count(t) from TotpEntity t where t.secret not like :pattern", Long.class)
                .setParameter("pattern", keyId + ":%")
                .getSingleResult());
  }

  @Override
  public long accountsWithRecoveryCodesNotUnderKey(String keyId) {
    return database.transaction(
        em ->
            em.createQuery("select count(distinct r.subject) from RecoveryCodeEntity r where r.codeHash not like :pattern", Long.class)
                .setParameter("pattern", keyId + ":%")
                .getSingleResult());
  }

  @Override
  public boolean useTotpStep(String subject, long step) {
    // One bulk update: of two concurrent uses of the same code, only one moves the step forward.
    return database.transaction(
            em ->
                em.createQuery("update TotpEntity t set t.lastUsedStep = :step where t.subject = :subject and t.lastUsedStep < :step")
                    .setParameter("step", step)
                    .setParameter("subject", subject)
                    .executeUpdate())
        == 1;
  }

  @Override
  public void replaceRecoveryCodes(String subject, List<String> codeHashes) {
    // One transaction: the old codes are gone and all the new ones exist, or nothing changed.
    database.transaction(
        em -> {
          em.createQuery("delete from RecoveryCodeEntity r where r.subject = :subject").setParameter("subject", subject).executeUpdate();
          codeHashes.forEach(hash -> em.persist(new RecoveryCodeEntity(subject, hash)));
          return null;
        });
  }

  @Override
  public boolean useRecoveryCode(String subject, String codeHash) {
    // One bulk delete: a code works once, even for two concurrent attempts.
    return database.transaction(
            em ->
                em.createQuery("delete from RecoveryCodeEntity r where r.subject = :subject and r.codeHash = :hash")
                    .setParameter("subject", subject)
                    .setParameter("hash", codeHash)
                    .executeUpdate())
        == 1;
  }

  @Override
  public int remainingRecoveryCodes(String subject) {
    return database.transaction(
        em ->
            em.createQuery("select count(r) from RecoveryCodeEntity r where r.subject = :subject", Long.class)
                .setParameter("subject", subject)
                .getSingleResult()
                .intValue());
  }

  @Override
  public void deleteRecoveryCodes(String subject) {
    database.transaction(
        em -> em.createQuery("delete from RecoveryCodeEntity r where r.subject = :subject").setParameter("subject", subject).executeUpdate());
  }

  @Override
  public long accountsWithTotp() {
    return database.transaction(em -> em.createQuery("select count(t) from TotpEntity t", Long.class).getSingleResult());
  }
}

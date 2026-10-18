package com.lattice.oidc.stores.jpa;

import com.lattice.oidc.stores.postgres.PostgresDatabase;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.EntityTransaction;
import jakarta.persistence.PersistenceConfiguration;
import jakarta.persistence.ValidationMode;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.inject.ApplicationLifecycle;

/**
 * JPA (Hibernate ORM) on top of {@link PostgresDatabase}: the same connection pool, and the schema
 * that Flyway created there. Hibernate never creates or changes tables; at startup it checks that
 * every entity matches the schema ({@code hibernate.hbm2ddl.auto = validate}), so a mapping that
 * disagrees with a migration stops the server rather than failing on the first request.
 *
 * <p>Each call runs in its own transaction on its own {@link EntityManager}, closed afterwards, the
 * way {@link PostgresDatabase} runs each statement on its own connection. Operations that must be
 * atomic stay single statements: a JPQL bulk update, or native SQL where JPQL has no equivalent
 * ({@code ON CONFLICT}, {@code RETURNING}).
 */
@Singleton
public final class JpaDatabase {

  private static final Logger LOG = LoggerFactory.getLogger(JpaDatabase.class);

  private final EntityManagerFactory factory;

  @Inject
  public JpaDatabase(PostgresDatabase database, ApplicationLifecycle lifecycle) {
    this.factory =
        new PersistenceConfiguration("lattice")
            // One entity per table in conf/db/migration, all validated against the schema at startup.
            .managedClass(UserEntity.class)
            .managedClass(PasskeyEntity.class)
            .managedClass(UserHandleEntity.class)
            .managedClass(PasskeyOfferEntity.class)
            .managedClass(IdentityLinkEntity.class)
            .managedClass(ObbConsentEntity.class)
            .managedClass(SessionEntity.class)
            .managedClass(SessionClientEntity.class)
            .managedClass(EphemeralEntity.class)
            .managedClass(CounterEntity.class)
            .managedClass(AuditEventEntity.class)
            .managedClass(TotpEntity.class)
            .managedClass(RecoveryCodeEntity.class)
            .managedClass(AppConsentEntity.class)
            // No Bean Validation of entities: they carry no constraints of their own (the schema's are
            // enforced by PostgreSQL), and Play's hibernate-validator would otherwise be picked up
            // automatically and fail to start without an expression-language library.
            .validationMode(ValidationMode.NONE)
            // Hibernate uses this pool rather than opening connections of its own.
            .property("hibernate.connection.datasource", database.dataSource())
            .property("hibernate.hbm2ddl.auto", "validate")
            .createEntityManagerFactory();
    // Registered after the pool's stop hook, so it runs first: the factory closes before the pool.
    lifecycle.addStopHook(
        () -> {
          factory.close();
          return CompletableFuture.completedFuture(null);
        });
    LOG.info("JPA ready (Hibernate, entities validated against the schema)");
  }

  /** A duration as seconds, for {@code make_interval(secs => ?)} in native SQL. */
  static double seconds(java.time.Duration duration) {
    return duration.toMillis() / 1000.0;
  }

  /** The rows of a native query that was created with an entity class. */
  @SuppressWarnings("unchecked")
  static <T> java.util.List<T> resultList(jakarta.persistence.Query query) {
    return (java.util.List<T>) query.getResultList();
  }

  /** Runs {@code work} in a transaction, committed if it returns and rolled back if it throws. */
  public <T> T transaction(Function<EntityManager, T> work) {
    try (EntityManager entityManager = factory.createEntityManager()) {
      EntityTransaction transaction = entityManager.getTransaction();
      transaction.begin();
      try {
        T result = work.apply(entityManager);
        transaction.commit();
        return result;
      } catch (RuntimeException e) {
        if (transaction.isActive()) {
          transaction.rollback();
        }
        throw e;
      }
    }
  }
}

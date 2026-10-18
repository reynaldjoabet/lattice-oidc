package com.lattice.oidc.stores.jpa;

import com.lattice.oidc.stores.IdentityLinkStore;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.List;
import java.util.Optional;

/** {@link IdentityLinkStore} through JPA (entity {@link IdentityLinkEntity}, table {@code identity_links}). */
@Singleton
public final class JpaIdentityLinkStore implements IdentityLinkStore {

  private final JpaDatabase database;

  @Inject
  public JpaIdentityLinkStore(JpaDatabase database) {
    this.database = database;
  }

  @Override
  public void link(String providerId, String externalSubject, String localSubject) {
    // Native SQL: an atomic upsert (an upstream account links to exactly one local account).
    database.transaction(
        em ->
            em.createNativeQuery(
                    """
                    INSERT INTO identity_links (provider_id, external_subject, local_subject) VALUES (?1, ?2, ?3)
                    ON CONFLICT (provider_id, external_subject) DO UPDATE SET local_subject = EXCLUDED.local_subject
                    """)
                .setParameter(1, providerId)
                .setParameter(2, externalSubject)
                .setParameter(3, localSubject)
                .executeUpdate());
  }

  @Override
  public Optional<String> localSubject(String providerId, String externalSubject) {
    return database.transaction(
        em ->
            Optional.ofNullable(em.find(IdentityLinkEntity.class, new IdentityLinkEntity.Key(providerId, externalSubject)))
                .map(link -> link.localSubject));
  }

  @Override
  public List<Link> linksOf(String localSubject) {
    return database.transaction(
        em ->
            em.createQuery(
                    "select l from IdentityLinkEntity l where l.localSubject = :subject order by l.createdAt", IdentityLinkEntity.class)
                .setParameter("subject", localSubject)
                .getResultStream()
                .map(l -> new Link(l.providerId, l.externalSubject, l.localSubject))
                .toList());
  }

  @Override
  public void unlink(String providerId, String externalSubject) {
    database.transaction(
        em ->
            em.createQuery("delete from IdentityLinkEntity l where l.providerId = :provider and l.externalSubject = :external")
                .setParameter("provider", providerId)
                .setParameter("external", externalSubject)
                .executeUpdate());
  }
}

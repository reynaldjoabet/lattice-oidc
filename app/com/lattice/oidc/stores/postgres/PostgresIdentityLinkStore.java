package com.lattice.oidc.stores.postgres;

import com.lattice.oidc.stores.IdentityLinkStore;
import java.util.List;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Singleton;

/** {@link IdentityLinkStore} in PostgreSQL (table {@code identity_links}). */
@Singleton
public final class PostgresIdentityLinkStore implements IdentityLinkStore {

  private final PostgresDatabase database;

  @Inject
  public PostgresIdentityLinkStore(PostgresDatabase database) {
    this.database = database;
  }

  @Override
  public void link(String providerId, String externalSubject, String localSubject) {
    database.update(
        """
        INSERT INTO identity_links (provider_id, external_subject, local_subject) VALUES (?, ?, ?)
        ON CONFLICT (provider_id, external_subject) DO UPDATE SET local_subject = EXCLUDED.local_subject
        """,
        providerId, externalSubject, localSubject);
  }

  @Override
  public Optional<String> localSubject(String providerId, String externalSubject) {
    return database.queryOne(
        "SELECT local_subject FROM identity_links WHERE provider_id = ? AND external_subject = ?",
        row -> row.getString(1),
        providerId, externalSubject);
  }

  @Override
  public List<Link> linksOf(String localSubject) {
    return database.query(
        "SELECT provider_id, external_subject, local_subject FROM identity_links WHERE local_subject = ?"
            + " ORDER BY created_at",
        row -> new Link(row.getString(1), row.getString(2), row.getString(3)),
        localSubject);
  }

  @Override
  public void unlink(String providerId, String externalSubject) {
    database.update(
        "DELETE FROM identity_links WHERE provider_id = ? AND external_subject = ?", providerId, externalSubject);
  }
}

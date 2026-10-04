package com.lattice.oidc.stores;

import com.google.inject.ImplementedBy;
import java.util.List;
import java.util.Optional;

/**
 * Links between upstream identities ({@code <provider id>, <subject at the provider>}) and local
 * accounts, created when a user confirms "Link accounts" after a brokered sign-in. Once linked, a
 * sign-in with that provider logs in to the local account instead of creating {@code sub@provider}.
 */
@ImplementedBy(InMemoryIdentityLinkStore.class)
public interface IdentityLinkStore {

  /** An upstream identity linked to a local account. */
  record Link(String providerId, String externalSubject, String localSubject) {}

  void link(String providerId, String externalSubject, String localSubject);

  /** The local account an upstream identity is linked to, if any. */
  Optional<String> localSubject(String providerId, String externalSubject);

  /** The upstream identities linked to a local account. */
  List<Link> linksOf(String localSubject);

  void unlink(String providerId, String externalSubject);
}

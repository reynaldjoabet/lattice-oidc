package com.lattice.oidc.stores;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import javax.inject.Singleton;

/**
 * Links between upstream identities ({@code <provider id>, <subject at the provider>}) and local
 * accounts, created when a user confirms "Link accounts" after a brokered sign-in. Once linked, a
 * sign-in with that provider logs in to the local account instead of creating {@code sub@provider}.
 *
 * <p>In memory, like {@link InMemoryUserStore}: replace both with database-backed stores for
 * production.
 */
@Singleton
public final class IdentityLinkStore {

  /** An upstream identity linked to a local account. */
  public record Link(String providerId, String externalSubject, String localSubject) {}

  private final Map<String, Link> byExternal = new ConcurrentHashMap<>();

  public void link(String providerId, String externalSubject, String localSubject) {
    byExternal.put(key(providerId, externalSubject), new Link(providerId, externalSubject, localSubject));
  }

  /** The local account an upstream identity is linked to, if any. */
  public Optional<String> localSubject(String providerId, String externalSubject) {
    return Optional.ofNullable(byExternal.get(key(providerId, externalSubject))).map(Link::localSubject);
  }

  /** The upstream identities linked to a local account. */
  public List<Link> linksOf(String localSubject) {
    List<Link> links = new ArrayList<>();
    for (Link link : byExternal.values()) {
      if (link.localSubject().equals(localSubject)) {
        links.add(link);
      }
    }
    return links;
  }

  private static String key(String providerId, String externalSubject) {
    return providerId + "|" + externalSubject;
  }
}

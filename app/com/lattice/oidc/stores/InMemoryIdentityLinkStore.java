package com.lattice.oidc.stores;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.inject.Singleton;

/** {@link IdentityLinkStore} in memory, for one server (development and tests). */
@Singleton
public final class InMemoryIdentityLinkStore implements IdentityLinkStore {

  private final Map<String, Link> byExternal = new ConcurrentHashMap<>();

  @Override
  public void link(String providerId, String externalSubject, String localSubject) {
    byExternal.put(key(providerId, externalSubject), new Link(providerId, externalSubject, localSubject));
  }

  @Override
  public Optional<String> localSubject(String providerId, String externalSubject) {
    return Optional.ofNullable(byExternal.get(key(providerId, externalSubject))).map(Link::localSubject);
  }

  @Override
  public List<Link> linksOf(String localSubject) {
    List<Link> links = new ArrayList<>();
    for (Link link : byExternal.values()) {
      if (link.localSubject().equals(localSubject)) {
        links.add(link);
      }
    }
    return links;
  }

  @Override
  public void unlink(String providerId, String externalSubject) {
    byExternal.remove(key(providerId, externalSubject));
  }

  private static String key(String providerId, String externalSubject) {
    return providerId + "|" + externalSubject;
  }
}

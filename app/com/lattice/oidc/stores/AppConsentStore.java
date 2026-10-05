package com.lattice.oidc.stores;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * What each account approved for each app on the consent page: the scopes and claims. A request
 * that asks for nothing more is issued without the page; one that asks for more shows it again.
 * Separate from {@link ConsentStore}, which holds Open Banking consents.
 */
public interface AppConsentStore {

  /** An account's approval for one app (Authlete's numeric client ID). */
  record AppConsent(String subject, long clientId, Set<String> scopes, Set<String> claims, Instant grantedAt) {

    /** Whether everything requested was already approved. */
    public boolean covers(Set<String> requestedScopes, Set<String> requestedClaims) {
      return scopes.containsAll(requestedScopes) && claims.containsAll(requestedClaims);
    }
  }

  Optional<AppConsent> find(String subject, long clientId);

  void put(AppConsent consent);

  /** Forgets one account's approval for one app (access removed from the account page). */
  void delete(String subject, long clientId);

  /** Forgets every approval for an app (the app was deleted). */
  void deleteClient(long clientId);

  /** Adds the scopes and claims to what the account already approved for the app. */
  default void approve(String subject, long clientId, Set<String> scopes, Set<String> claims) {
    Set<String> allScopes = new TreeSet<>(scopes);
    Set<String> allClaims = new TreeSet<>(claims);
    find(subject, clientId)
        .ifPresent(
            existing -> {
              allScopes.addAll(existing.scopes());
              allClaims.addAll(existing.claims());
            });
    put(new AppConsent(subject, clientId, Set.copyOf(allScopes), Set.copyOf(allClaims), Instant.now()));
  }

  /** Whether the account already approved everything requested for the app. */
  default boolean covers(String subject, long clientId, Set<String> scopes, Set<String> claims) {
    return find(subject, clientId).map(consent -> consent.covers(scopes, claims)).orElse(false);
  }
}

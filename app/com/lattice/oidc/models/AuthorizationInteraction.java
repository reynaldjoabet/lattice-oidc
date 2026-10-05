package com.lattice.oidc.models;

import com.authlete.common.dto.AuthorizationResponse;
import com.authlete.common.dto.Scope;
import com.authlete.common.dto.StringArray;
import com.authlete.common.types.Prompt;
import com.authlete.common.types.SubjectType;
import java.util.Arrays;
import java.util.Set;

/** Server-side state of a pending authorization (keyed by Authlete ticket, bound to the browser). */
public record AuthorizationInteraction(
    String ticket,
    AuthorizationPage page,
    String[] claimNames,
    String[] claimLocales,
    String idTokenClaims,
    String[] requestedClaimsForTx,
    StringArray[] requestedVerifiedClaimsForTx,
    String[] acrs,
    boolean acrEssential,
    String requestedSubject,
    long clientId,
    String clientIdentifier,
    SubjectType subjectType,
    String sectorIdentifier,
    String shownSubject,
    String[] scopes,
    boolean consentPrompted) {

  public static AuthorizationInteraction from(
      AuthorizationResponse info, AuthorizationPage page, String shownSubject) {
    var client = info.getClient();
    String identifier =
        client.isClientIdAliasEnabled() && client.getClientIdAlias() != null
            ? client.getClientIdAlias()
            : String.valueOf(client.getClientId());
    return new AuthorizationInteraction(
        info.getTicket(),
        page,
        info.getClaims(),
        info.getClaimsLocales(),
        info.getIdTokenClaims(),
        info.getRequestedClaimsForTx(),
        info.getRequestedVerifiedClaimsForTx(),
        info.getAcrs(),
        info.isAcrEssential(),
        info.getSubject(),
        client.getClientId(),
        identifier,
        client.getSubjectType(),
        client.getDerivedSectorIdentifier(),
        shownSubject,
        info.getScopes() == null
            ? new String[0]
            : Arrays.stream(info.getScopes()).map(Scope::getName).toArray(String[]::new),
        info.getPrompts() != null && Arrays.asList(info.getPrompts()).contains(Prompt.CONSENT));
  }

  /** The requested scopes. */
  public Set<String> scopeSet() {
    return scopes == null ? Set.of() : Set.copyOf(Arrays.asList(scopes));
  }

  /** The requested claims. */
  public Set<String> claimSet() {
    return claimNames == null ? Set.of() : Set.copyOf(Arrays.asList(claimNames));
  }

  /**
   * Whether an earlier approval can stand in for the consent page. Never for an Open Banking
   * consent (each is a separate agreement), identity-verification claims, or claims about a
   * transaction: those are approved each time.
   */
  public boolean approvalCanBeRemembered() {
    boolean openBanking = scopeSet().stream().anyMatch(scope -> scope.startsWith("consent:"));
    boolean verifiedClaims =
        (idTokenClaims != null && idTokenClaims.contains("verified_claims"))
            || (requestedVerifiedClaimsForTx != null && requestedVerifiedClaimsForTx.length > 0);
    boolean transactionClaims = requestedClaimsForTx != null && requestedClaimsForTx.length > 0;
    return !openBanking && !verifiedClaims && !transactionClaims;
  }

  public AuthorizationInteraction withPage(AuthorizationPage newPage) {
    return new AuthorizationInteraction(
        ticket, newPage, claimNames, claimLocales, idTokenClaims, requestedClaimsForTx,
        requestedVerifiedClaimsForTx, acrs, acrEssential, requestedSubject, clientId,
        clientIdentifier, subjectType, sectorIdentifier, shownSubject, scopes, consentPrompted);
  }

  public AuthorizationInteraction withShownSubject(String subject) {
    return new AuthorizationInteraction(
        ticket, page, claimNames, claimLocales, idTokenClaims, requestedClaimsForTx,
        requestedVerifiedClaimsForTx, acrs, acrEssential, requestedSubject, clientId,
        clientIdentifier, subjectType, sectorIdentifier, subject, scopes, consentPrompted);
  }
}

package com.lattice.oidc.authorization;

import com.authlete.common.dto.AuthorizationResponse;
import com.authlete.common.dto.StringArray;
import com.authlete.common.types.SubjectType;

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
    String shownSubject) {

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
        shownSubject);
  }

  public AuthorizationInteraction withPage(AuthorizationPage newPage) {
    return new AuthorizationInteraction(
        ticket, newPage, claimNames, claimLocales, idTokenClaims, requestedClaimsForTx,
        requestedVerifiedClaimsForTx, acrs, acrEssential, requestedSubject, clientId,
        clientIdentifier, subjectType, sectorIdentifier, shownSubject);
  }

  public AuthorizationInteraction withShownSubject(String subject) {
    return new AuthorizationInteraction(
        ticket, page, claimNames, claimLocales, idTokenClaims, requestedClaimsForTx,
        requestedVerifiedClaimsForTx, acrs, acrEssential, requestedSubject, clientId,
        clientIdentifier, subjectType, sectorIdentifier, subject);
  }
}

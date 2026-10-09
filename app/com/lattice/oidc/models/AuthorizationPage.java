package com.lattice.oidc.models;

import com.authlete.common.dto.AuthorizationResponse;
import com.authlete.common.dto.AuthzDetails;
import com.authlete.common.dto.Client;
import com.authlete.common.dto.DynamicScope;
import com.authlete.common.dto.Scope;
import com.lattice.oidc.common.JsonHelpers;
import com.lattice.oidc.handlers.IdentityProviders;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Everything the consent page shows. Immutable; derived variants are created with {@code with*}. */
public record AuthorizationPage(
    String ticket,
    String serviceName,
    String clientName,
    Optional<String> description,
    Optional<String> logoUri,
    Optional<String> clientUri,
    Optional<String> policyUri,
    Optional<String> tosUri,
    List<ScopeItem> scopes,
    List<String> claimsForIdToken,
    List<String> claimsForUserInfo,
    Optional<String> purpose,
    List<ClaimPurpose> verifiedClaimsForIdToken,
    List<ClaimPurpose> verifiedClaimsForUserInfo,
    Optional<String> authorizationDetails,
    String loginId,
    boolean loginIdReadOnly,
    Optional<String> loggedInAs,
    List<IdentityProviders.Link> identityProviders,
    Optional<String> error,
    Optional<ObbConsentView> obbConsent,
    boolean identified) {

  /** A requested scope and its plain-language description. */
  public record ScopeItem(String name, String description) {}

  public record ClaimPurpose(String claim, String purpose) {}

  public static AuthorizationPage from(
      AuthorizationResponse info, Optional<String> loggedInAs, List<IdentityProviders.Link> identityProviders) {
    Client client = info.getClient();
    String clientName =
        client.getClientName() != null
            ? client.getClientName()
            : String.valueOf(client.getClientId());
    String loginId =
        info.getSubject() != null
            ? info.getSubject()
            : info.getLoginHint() != null ? info.getLoginHint() : "";
    List<ClaimPurpose> idTokenVerifiedClaims = verifiedClaims(info.getIdTokenClaims());
    List<ClaimPurpose> userInfoVerifiedClaims = verifiedClaims(info.getUserInfoClaims());
    return new AuthorizationPage(
        info.getTicket(),
        info.getService() != null && info.getService().getServiceName() != null
            ? info.getService().getServiceName()
            : "Lattice",
        clientName,
        Optional.ofNullable(client.getDescription()),
        uri(client.getLogoUri()),
        uri(client.getClientUri()),
        uri(client.getPolicyUri()),
        uri(client.getTosUri()),
        scopes(info),
        list(info.getClaims()),
        list(info.getClaimsAtUserInfo()),
        Optional.ofNullable(info.getPurpose()),
        idTokenVerifiedClaims,
        userInfoVerifiedClaims,
        details(info.getAuthorizationDetails()),
        loginId,
        info.getSubject() != null,
        loggedInAs,
        identityProviders,
        Optional.empty(),
        Optional.empty(),
        info.getSubject() != null || info.getLoginHint() != null);
  }

  public AuthorizationPage withError(String message) {
    return new AuthorizationPage(
        ticket, serviceName, clientName, description, logoUri, clientUri, policyUri, tosUri, scopes,
        claimsForIdToken, claimsForUserInfo, purpose, verifiedClaimsForIdToken,
        verifiedClaimsForUserInfo, authorizationDetails, loginId, loginIdReadOnly, loggedInAs,
        identityProviders, Optional.ofNullable(message), obbConsent, identified);
  }

  public AuthorizationPage withLoggedInAs(Optional<String> user) {
    return new AuthorizationPage(
        ticket, serviceName, clientName, description, logoUri, clientUri, policyUri, tosUri, scopes,
        claimsForIdToken, claimsForUserInfo, purpose, verifiedClaimsForIdToken,
        verifiedClaimsForUserInfo, authorizationDetails, loginId, loginIdReadOnly, user,
        identityProviders, error, obbConsent, identified);
  }

  /** The page for an Open Banking consent ({@code consent:...} scope). */
  public AuthorizationPage withObbConsent(Optional<ObbConsentView> consent) {
    return new AuthorizationPage(
        ticket, serviceName, clientName, description, logoUri, clientUri, policyUri, tosUri, scopes,
        claimsForIdToken, claimsForUserInfo, purpose, verifiedClaimsForIdToken,
        verifiedClaimsForUserInfo, authorizationDetails, loginId, loginIdReadOnly, loggedInAs,
        identityProviders, error, consent, identified);
  }

  /**
   * After the email-first step: the sign-in page asks for the password of {@code identifier}. A
   * null identifier goes back to the first step.
   */
  public AuthorizationPage withIdentifier(String identifier) {
    return new AuthorizationPage(
        ticket, serviceName, clientName, description, logoUri, clientUri, policyUri, tosUri, scopes,
        claimsForIdToken, claimsForUserInfo, purpose, verifiedClaimsForIdToken,
        verifiedClaimsForUserInfo, authorizationDetails, identifier == null ? "" : identifier,
        loginIdReadOnly, loggedInAs, identityProviders, error, obbConsent, identifier != null);
  }

  /** Up to two initials of the client name, for the monogram shown when it has no logo. */
  public String clientInitials() {
    return Initials.of(clientName);
  }

  /** Scopes shown as permissions: the consent:... scope is described by the consent itself. */
  public List<ScopeItem> displayScopes() {
    return scopes.stream().filter(s -> !s.name().startsWith("consent:")).toList();
  }

  /**
   * What the application will receive about the user, in plain language and without duplicates
   * (claims for the ID token and for UserInfo, plus verified claims).
   */
  public List<String> sharedInformation() {
    java.util.LinkedHashSet<String> labels = new java.util.LinkedHashSet<>();
    claimsForIdToken.forEach(c -> labels.add(ConsentLabels.claim(c)));
    claimsForUserInfo.forEach(c -> labels.add(ConsentLabels.claim(c)));
    verifiedClaimsForIdToken.forEach(c -> labels.add("Verified: " + ConsentLabels.claim(c.claim())));
    verifiedClaimsForUserInfo.forEach(c -> labels.add("Verified: " + ConsentLabels.claim(c.claim())));
    return List.copyOf(labels);
  }

  /** Whether the protocol-level details section has anything to show. */
  public boolean hasTechnicalDetails() {
    return !claimsForIdToken.isEmpty()
        || !claimsForUserInfo.isEmpty()
        || authorizationDetails.isPresent()
        || identityAssuranceRequested();
  }

  public boolean identityAssuranceRequested() {
    return purpose.isPresent()
        || !verifiedClaimsForIdToken.isEmpty()
        || !verifiedClaimsForUserInfo.isEmpty();
  }

  private static Optional<String> uri(URI uri) {
    return uri == null ? Optional.empty() : Optional.of(uri.toString());
  }

  private static List<String> list(String[] values) {
    return values == null ? List.of() : Arrays.asList(values);
  }

  private static List<ScopeItem> scopes(AuthorizationResponse info) {
    List<ScopeItem> out = new ArrayList<>();
    if (info.getScopes() != null) {
      for (Scope s : info.getScopes()) {
        out.add(new ScopeItem(s.getName(), ConsentLabels.scope(s.getName(), s.getDescription())));
      }
    }
    if (info.getDynamicScopes() != null) {
      for (DynamicScope dynamicScope : info.getDynamicScopes()) {
        out.add(new ScopeItem(dynamicScope.getValue(), ConsentLabels.scope(dynamicScope.getValue(), null)));
      }
    }
    return out;
  }

  private static Optional<String> details(AuthzDetails details) {
    if (details == null || details.getElements() == null || details.getElements().length == 0) {
      return Optional.empty();
    }
    return Optional.of(JsonHelpers.pretty(JsonHelpers.readList(details.toJson())));
  }

  /** Claim names and purposes inside {@code verified_claims} of a claims request. */
  @SuppressWarnings("unchecked")
  private static List<ClaimPurpose> verifiedClaims(String claimsRequest) {
    if (claimsRequest == null || claimsRequest.isEmpty()) {
      return List.of();
    }
    Object verified = JsonHelpers.readMap(claimsRequest).get("verified_claims");
    List<Object> entries =
        verified instanceof List<?> l ? (List<Object>) l : verified == null ? List.of() : List.of(verified);
    List<ClaimPurpose> out = new ArrayList<>();
    for (Object e : entries) {
      if (e instanceof Map<?, ?> m && m.get("claims") instanceof Map<?, ?> claims) {
        claims.forEach(
            (name, spec) ->
                out.add(
                    new ClaimPurpose(
                        String.valueOf(name),
                        spec instanceof Map<?, ?> s && s.get("purpose") instanceof String p
                            ? p
                            : "")));
      }
    }
    return out;
  }
}

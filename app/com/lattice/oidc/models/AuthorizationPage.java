package com.lattice.oidc.models;

import com.authlete.common.dto.AuthorizationResponse;
import com.authlete.common.dto.AuthzDetails;
import com.authlete.common.dto.Client;
import com.authlete.common.dto.DynamicScope;
import com.authlete.common.dto.Scope;
import com.lattice.oidc.common.Jsons;
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
    Optional<String> error) {

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
    List<ClaimPurpose> idt = verifiedClaims(info.getIdTokenClaims());
    List<ClaimPurpose> ui = verifiedClaims(info.getUserInfoClaims());
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
        idt,
        ui,
        details(info.getAuthorizationDetails()),
        loginId,
        info.getSubject() != null,
        loggedInAs,
        identityProviders,
        Optional.empty());
  }

  public AuthorizationPage withError(String message) {
    return new AuthorizationPage(
        ticket, serviceName, clientName, description, logoUri, clientUri, policyUri, tosUri, scopes,
        claimsForIdToken, claimsForUserInfo, purpose, verifiedClaimsForIdToken,
        verifiedClaimsForUserInfo, authorizationDetails, loginId, loginIdReadOnly, loggedInAs,
        identityProviders, Optional.ofNullable(message));
  }

  public AuthorizationPage withLoggedInAs(Optional<String> user) {
    return new AuthorizationPage(
        ticket, serviceName, clientName, description, logoUri, clientUri, policyUri, tosUri, scopes,
        claimsForIdToken, claimsForUserInfo, purpose, verifiedClaimsForIdToken,
        verifiedClaimsForUserInfo, authorizationDetails, loginId, loginIdReadOnly, user,
        identityProviders, error);
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
      for (DynamicScope ds : info.getDynamicScopes()) {
        out.add(new ScopeItem(ds.getValue(), ConsentLabels.scope(ds.getValue(), null)));
      }
    }
    return out;
  }

  private static Optional<String> details(AuthzDetails details) {
    if (details == null || details.getElements() == null || details.getElements().length == 0) {
      return Optional.empty();
    }
    return Optional.of(Jsons.pretty(Jsons.readList(details.toJson())));
  }

  /** Claim names and purposes inside {@code verified_claims} of a claims request. */
  @SuppressWarnings("unchecked")
  private static List<ClaimPurpose> verifiedClaims(String claimsRequest) {
    if (claimsRequest == null || claimsRequest.isEmpty()) {
      return List.of();
    }
    Object vc = Jsons.readMap(claimsRequest).get("verified_claims");
    List<Object> entries =
        vc instanceof List<?> l ? (List<Object>) l : vc == null ? List.of() : List.of(vc);
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

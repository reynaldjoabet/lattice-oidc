package com.lattice.oidc.handlers;

import com.authlete.common.dto.CredentialIssuanceOrder;
import com.authlete.common.dto.CredentialRequestInfo;
import com.authlete.common.dto.IntrospectionResponse;
import com.lattice.oidc.common.JsonHelpers;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.UserStore;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/**
 * Turns parsed credential requests into issuance orders: checks the access token permits the
 * credential, then builds the payload from the user's data.
 *
 * <ul>
 *   <li>SD-JWT ({@code dc+sd-jwt}, {@code vc+sd-jwt}): claims listed per credential type ({@code vct}).
 *   <li>mdoc ({@code mso_mdoc}): namespaces stored as a user attribute keyed by doctype, filtered to
 *       the claims declared in the credential configuration.
 * </ul>
 *
 * Both OID4VCI 1.0 (credential_configuration_id / credential_identifier) and the ID1 draft
 * (format + vct/doctype in the request) are supported.
 */
@Singleton
public final class CredentialOrderHandler {

  public enum Context {
    SINGLE,
    BATCH,
    DEFERRED
  }

  /** Credential types this issuer can fill from user claims. */
  private static final Map<String, List<String>> SD_JWT_TYPES =
      Map.of(
          "https://credentials.example.com/identity_credential",
              List.of("given_name", "family_name", "birthdate"),
          "https://credentials.example.com/digital_credential",
              List.of("given_name", "family_name", "birthdate"),
          "urn:eu.europa.ec.eudi:pid:1",
              List.of(
                  "family_name", "given_name", "birthdate", "age_equal_or_over", "place_of_birth",
                  "address", "issuing_authority", "issuing_country"));

  private static final String MDL_NAMESPACE = "org.iso.18013.5.1";
  private static final long SD_JWT_DURATION = 30L * 24 * 60 * 60;

  private final UserStore users;

  @Inject
  public CredentialOrderHandler(UserStore users) {
    this.users = users;
  }

  public CredentialIssuanceOrder toOrder(Context context, IntrospectionResponse token, CredentialRequestInfo info)
      throws CredentialRequestException {
    String format = info.getFormat();
    boolean sdJwt = "dc+sd-jwt".equals(format) || "vc+sd-jwt".equals(format);
    boolean mdoc = "mso_mdoc".equals(format);
    if (!sdJwt && !mdoc) {
      throw new CredentialRequestException(
          "unsupported_credential_format", "The credential format '" + format + "' is not supported.");
    }
    User user =
        users.bySubject(token.getSubject())
            .orElseThrow(() -> CredentialRequestException.invalidRequest("Unknown credential subject."));
    List<Map<String, Object>> issuable = issuable(token);
    Map<String, Object> claims =
        sdJwt ? sdJwtClaims(issuable, info, user) : mdocClaims(issuable, info, user);
    String payload = claims == null ? null : JsonHelpers.write(claims);
    return new CredentialIssuanceOrder()
        .setRequestIdentifier(info.getIdentifier())
        .setCredentialPayload(payload)
        .setIssuanceDeferred(payload == null)
        .setCredentialDuration(sdJwt ? SD_JWT_DURATION : oneYearSeconds());
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> issuable(IntrospectionResponse token)
      throws CredentialRequestException {
    String json = token.getIssuableCredentials();
    if (json == null) {
      throw CredentialRequestException.invalidRequest("No credential can be issued with the access token.");
    }
    return (List<Map<String, Object>>) (List<?>) JsonHelpers.readList(json);
  }

  private static boolean isDraft(CredentialRequestInfo info) {
    return info.getCredentialConfigurationId() == null && info.getCredentialIdentifier() == null;
  }

  /** The issuable credential matching a 1.0-style request, or an error. */
  private static Map<String, Object> matching(List<Map<String, Object>> issuable, CredentialRequestInfo info)
      throws CredentialRequestException {
    for (Map<String, Object> c : issuable) {
      if (info.getCredentialConfigurationId() != null
          && Objects.equals(c.get("credential_configuration_id"), info.getCredentialConfigurationId())) {
        return c;
      }
      if (info.getCredentialIdentifier() != null
          && c.get("credential_identifiers") instanceof List<?> ids
          && ids.contains(info.getCredentialIdentifier())) {
        return c;
      }
    }
    throw CredentialRequestException.invalidRequest(
        "The access token does not permit requesting this credential.");
  }

  private Map<String, Object> sdJwtClaims(
      List<Map<String, Object>> issuable, CredentialRequestInfo info, User user)
      throws CredentialRequestException {
    String vct;
    if (isDraft(info)) {
      Object requested = JsonHelpers.readMap(info.getDetails()).get("vct");
      if (!(requested instanceof String v)) {
        throw CredentialRequestException.invalidRequest("The credential request does not contain 'vct'.");
      }
      boolean permitted =
          issuable.stream()
              .anyMatch(c -> info.getFormat().equals(c.get("format")) && v.equals(c.get("vct")));
      if (!permitted) {
        throw CredentialRequestException.invalidRequest(
            "The access token does not permit requesting this credential.");
      }
      vct = v;
    } else {
      vct = String.valueOf(matching(issuable, info).get("vct"));
    }
    List<String> claimNames = SD_JWT_TYPES.get(vct);
    if (claimNames == null) {
      throw new CredentialRequestException("unsupported_credential_type", "The vct '" + vct + "' is not supported.");
    }
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("vct", vct);
    claims.put("sub", user.getSubject());
    for (String name : claimNames) {
      Object value = user.getClaim(name, null);
      if (value != null) {
        claims.put(name, value);
      }
    }
    return claims;
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> mdocClaims(
      List<Map<String, Object>> issuable, CredentialRequestInfo info, User user)
      throws CredentialRequestException {
    String docType;
    Map<String, Object> requested;
    if (isDraft(info)) {
      Map<String, Object> details = JsonHelpers.readMap(info.getDetails());
      if (!(details.get("doctype") instanceof String d)) {
        throw CredentialRequestException.invalidRequest("The credential request does not contain 'doctype'.");
      }
      boolean permitted =
          issuable.stream().anyMatch(c -> info.getFormat().equals(c.get("format")) && d.equals(c.get("doctype")));
      if (!permitted) {
        throw CredentialRequestException.invalidRequest(
            "The access token does not permit requesting this credential.");
      }
      docType = d;
      Object claims = details.get("claims");
      if (claims != null && !(claims instanceof Map)) {
        throw CredentialRequestException.invalidRequest("'claims' must be a JSON object.");
      }
      requested = (Map<String, Object>) claims;
    } else {
      Map<String, Object> c = matching(issuable, info);
      docType = String.valueOf(c.get("doctype"));
      requested = declaredClaims(c);
    }
    Map<String, Object> userData =
        user.getAttribute(docType) instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
    Map<String, Object> namespaces = new LinkedHashMap<>();
    if (requested != null) {
      for (Map.Entry<String, Object> ns : requested.entrySet()) {
        if (!(userData.get(ns.getKey()) instanceof Map<?, ?> values) || !(ns.getValue() instanceof Map<?, ?> wanted)) {
          continue;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        if (MDL_NAMESPACE.equals(ns.getKey())) {
          ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
          if (wanted.containsKey("issue_date")) {
            out.put("issue_date", fullDate(now));
          }
          if (wanted.containsKey("expiry_date")) {
            out.put("expiry_date", fullDate(now.plusYears(1)));
          }
        }
        for (Object name : wanted.keySet()) {
          if (values.containsKey(name)) {
            out.put((String) name, values.get(name));
          }
        }
        namespaces.put(ns.getKey(), out);
      }
    }
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("doctype", docType);
    payload.put("claims", namespaces);
    return payload;
  }

  /** Namespace/claim pairs declared in credential_metadata.claims[].path of the configuration. */
  private static Map<String, Object> declaredClaims(Map<String, Object> issuable) {
    Map<String, Object> out = new LinkedHashMap<>();
    if (issuable.get("credential_metadata") instanceof Map<?, ?> meta && meta.get("claims") instanceof List<?> claims) {
      for (Object c : claims) {
        if (c instanceof Map<?, ?> claim
            && claim.get("path") instanceof List<?> path
            && path.size() >= 2
            && path.get(0) instanceof String ns
            && path.get(1) instanceof String name) {
          @SuppressWarnings("unchecked")
          Map<String, Object> nsMap = (Map<String, Object>) out.computeIfAbsent(ns, k -> new LinkedHashMap<>());
          nsMap.put(name, Map.of());
        }
      }
    }
    return out;
  }

  private static String fullDate(ZonedDateTime dt) {
    return "cbor:1004(\"" + dt.format(DateTimeFormatter.ISO_LOCAL_DATE) + "\")";
  }

  private static long oneYearSeconds() {
    ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
    return ChronoUnit.SECONDS.between(now, now.plusYears(1));
  }
}

package com.lattice.oidc.handlers;

import com.authlete.common.dto.StringArray;
import com.authlete.common.ida.DatasetExtractor;
import com.lattice.oidc.common.JsonHelpers;
import com.lattice.oidc.models.User;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.slf4j.LoggerFactory;

/**
 * Gathers claim values for ID tokens and UserInfo responses, including OpenID Connect for Identity
 * Assurance {@code verified_claims} and transaction-scoped ({@code _for_tx}) claims.
 */
public final class ClaimsCollector {

  private static final String VERIFIED_CLAIMS = "verified_claims";
  private static final String CLAIMS = "claims";

  private final User user;

  public ClaimsCollector(User user) {
    this.user = user;
  }

  /**
   * Values of the requested claims. A name may carry a language tag ({@code name#ja}); without one,
   * the requested locales are tried in order before the untagged value.
   */
  public Map<String, Object> collect(String[] claimNames, String[] claimLocales) {
    if (claimNames == null || claimNames.length == 0) {
      return null;
    }
    // Drop empty and duplicate entries from claimLocales.
    String[] locales = normalizeLocales(claimLocales);
    Map<String, Object> claims = new LinkedHashMap<>();
    for (String claimName : claimNames) {
      if (claimName == null || claimName.isEmpty()) {
        continue;
      }
      // Split the claim name into the name part and the tag part (e.g. "name#ja").
      String[] parts = claimName.split("#", 2);
      String name = parts[0];
      String tag = parts.length == 2 ? parts[1] : null;
      if (name.isEmpty()) {
        continue;
      }
      // Get the claim value: with the specific language tag if one is appended, otherwise trying the
      // requested claim locales in order of preference.
      Object value = tag != null ? user.getClaim(name, tag) : localized(name, locales);
      if (value != null) {
        // Add the pair of the claim name and the claim value ("name" also covers the edge case where the
        // claim name ends with "#").
        claims.put(tag == null ? name : claimName, value);
      }
    }
    return claims.isEmpty() ? null : claims;
  }

  /**
   * The claim value for the first claim locale that has one; the last resort is the value without any
   * language tag.
   */
  private Object localized(String name, String[] locales) {
    if (locales != null) {
      for (String locale : locales) {
        Object v = user.getClaim(name, locale);
        if (v != null) {
          return v;
        }
      }
    }
    return user.getClaim(name, null);
  }

  /**
   * Drops empty and duplicate claim locales.
   *
   * <p>From 5.2. Claims Languages and Scripts in OpenID Connect Core 1.0: "However, since BCP47
   * language tag values are case insensitive, implementations SHOULD interpret the language tag values
   * supplied in a case insensitive manner."
   */
  private static String[] normalizeLocales(String[] locales) {
    if (locales == null) {
      return null;
    }
    Set<String> seen = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
    List<String> ordered = new ArrayList<>();
    for (String l : locales) {
      if (l != null && !l.isEmpty() && seen.add(l)) {
        ordered.add(l);
      }
    }
    return ordered.isEmpty() ? null : ordered.toArray(String[]::new);
  }

  /** Adds {@code verified_claims} matching the claims request (a JSON string) to {@code claims}. */
  public Map<String, Object> withVerifiedClaims(Map<String, Object> claims, String claimsRequest) {
    Object request = verifiedClaimsRequest(claimsRequest);
    if (request == null) {
      return claims;
    }
    Object value = verifiedClaims(request);
    if (value == null) {
      return claims;
    }
    Map<String, Object> out = claims == null ? new LinkedHashMap<>() : claims;
    out.put(VERIFIED_CLAIMS, value);
    return out;
  }

  /** The {@code verified_claims} values for transaction claims ({@code _for_tx}). */
  @SuppressWarnings("unchecked")
  public List<Map<String, Object>> verifiedClaimsForTx(
      String claimsRequest, StringArray[] requestedForTx) {
    if (requestedForTx == null) {
      return null;
    }
    Object request = verifiedClaimsRequest(claimsRequest);
    List<Map<String, Object>> requests =
        request instanceof List<?> l
            ? (List<Map<String, Object>>) l
            : request instanceof Map<?, ?> m ? List.of((Map<String, Object>) m) : null;
    if (requests == null || requests.size() != requestedForTx.length) {
      return null;
    }
    List<Map<String, Object>> out = new ArrayList<>();
    for (int i = 0; i < requests.size(); i++) {
      String[] names = requestedForTx[i] == null ? null : requestedForTx[i].getArray();
      Map<String, Object> claims = forTx(new HashMap<>(requests.get(i)), names);
      if (claims != null) {
        out.add(claims);
      }
    }
    return out.isEmpty() ? null : out;
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> forTx(Map<String, Object> request, String[] names) {
    if (names == null || names.length == 0) {
      return verifiedClaims(request) != null ? Collections.emptyMap() : null;
    }
    Map<String, Object> wanted = new HashMap<>();
    for (String n : names) {
      wanted.put(n, null);
    }
    request.put(CLAIMS, wanted);
    Object dataset = verifiedClaims(request);
    if (!(dataset instanceof Map<?, ?> map)) {
      return null;
    }
    Object claims = map.get(CLAIMS);
    return claims instanceof Map<?, ?> c ? (Map<String, Object>) c : Collections.emptyMap();
  }

  @SuppressWarnings("unchecked")
  private Object verifiedClaims(Object request) {
    List<Map<String, Object>> datasets = user.verifiedClaims();
    if (datasets.isEmpty()) {
      return null;
    }
    DatasetExtractor extractor =
        new DatasetExtractor().setLogger(LoggerFactory.getLogger(ClaimsCollector.class));
    if (request instanceof List<?> list) {
      List<Map<String, Object>> results = new ArrayList<>();
      for (Object r : list) {
        if (r instanceof Map<?, ?> m) {
          Map<String, Object> v = extractor.extract((Map<String, Object>) m, datasets);
          if (v != null) {
            results.add(v);
          }
        }
      }
      return results.isEmpty() ? null : results;
    }
    if (request instanceof Map<?, ?> m) {
      return extractor.extract((Map<String, Object>) m, datasets);
    }
    return null;
  }

  private static Object verifiedClaimsRequest(String claimsRequest) {
    if (claimsRequest == null || claimsRequest.isEmpty()) {
      return null;
    }
    return JsonHelpers.readMap(claimsRequest).get(VERIFIED_CLAIMS);
  }
}

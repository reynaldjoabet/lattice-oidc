package com.lattice.oidc.models;

import com.lattice.oidc.common.JsonHelpers;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Checks the identity-verification data an operator attaches to an account: the {@code
 * verified_claims} datasets that OpenID Connect for Identity Assurance releases in ID tokens and
 * userinfo responses.
 *
 * <p>Lattice does not verify identities itself. A KYC process (in person, a document check, an eKYC
 * provider) does, and its result is stored on the account in the shape the specification uses for
 * output: a JSON array of objects, each with a {@code verification} object (at least the {@code
 * trust_framework} the check followed) and a non-empty {@code claims} object (the values that were
 * verified). When a client asks for verified claims, Authlete's {@code DatasetExtractor} picks the
 * datasets and fields that match its request (see {@code ClaimsCollector}).
 *
 * <p>Only the structure the extractor relies on is checked here, not every rule of the
 * specification: the operator is trusted, and the release is filtered by the request anyway.
 */
public final class VerifiedClaimsData {

  /** The datasets, or why they were refused. */
  public record Parsed(List<Map<String, Object>> datasets, List<String> problems) {
    public boolean ok() {
      return problems.isEmpty();
    }
  }

  private VerifiedClaimsData() {}

  /** Parses {@code json}: an array of datasets, a single dataset, or empty for none. */
  @SuppressWarnings("unchecked")
  public static Parsed parse(String json) {
    if (json == null || json.isBlank()) {
      return new Parsed(List.of(), List.of());
    }
    Object value;
    try {
      value = JsonHelpers.read(json, Object.class);
    } catch (RuntimeException e) {
      return new Parsed(List.of(), List.of("This is not valid JSON."));
    }
    List<Object> items = value instanceof List<?> list ? (List<Object>) list : value instanceof Map<?, ?> ? List.of(value) : null;
    if (items == null) {
      return new Parsed(List.of(), List.of("Enter a JSON array of verified_claims objects."));
    }
    List<String> problems = new ArrayList<>();
    List<Map<String, Object>> datasets = new ArrayList<>();
    for (int i = 0; i < items.size(); i++) {
      String where = items.size() == 1 ? "The dataset" : "Dataset " + (i + 1);
      if (!(items.get(i) instanceof Map<?, ?> item)) {
        problems.add(where + " is not a JSON object.");
        continue;
      }
      if (!(item.get("verification") instanceof Map<?, ?> verification)) {
        problems.add(where + " has no \"verification\" object.");
      } else if (!(verification.get("trust_framework") instanceof String framework) || framework.isBlank()) {
        problems.add(where + " has no \"verification.trust_framework\".");
      }
      if (!(item.get("claims") instanceof Map<?, ?> claims) || claims.isEmpty()) {
        problems.add(where + " has no \"claims\", or they are empty.");
      }
      datasets.add((Map<String, Object>) item);
    }
    return problems.isEmpty() ? new Parsed(List.copyOf(datasets), List.of()) : new Parsed(List.of(), problems);
  }

  /** The datasets as indented JSON, for the editor; empty for none. */
  public static String pretty(List<Map<String, Object>> datasets) {
    return datasets.isEmpty() ? "" : JsonHelpers.pretty(datasets);
  }
}

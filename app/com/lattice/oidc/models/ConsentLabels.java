package com.lattice.oidc.models;

import java.util.Map;

/**
 * Plain-language labels for standard scopes and claims, so the consent page tells end-users what
 * is shared instead of showing protocol identifiers. Unknown names fall back to the identifier.
 */
public final class ConsentLabels {
  private ConsentLabels() {}

  private static final Map<String, String> SCOPES =
      Map.ofEntries(
          Map.entry("openid", "Sign you in with your account"),
          Map.entry("profile", "Your basic profile (name, picture, locale)"),
          Map.entry("email", "Your email address"),
          Map.entry("address", "Your postal address"),
          Map.entry("phone", "Your phone number"),
          Map.entry("offline_access", "Keep access when you are not using the application"));

  private static final Map<String, String> CLAIMS =
      Map.ofEntries(
          Map.entry("sub", "Your account identifier"),
          Map.entry("name", "Full name"),
          Map.entry("given_name", "First name"),
          Map.entry("family_name", "Last name"),
          Map.entry("middle_name", "Middle name"),
          Map.entry("nickname", "Nickname"),
          Map.entry("preferred_username", "Username"),
          Map.entry("profile", "Profile page"),
          Map.entry("picture", "Profile picture"),
          Map.entry("website", "Website"),
          Map.entry("email", "Email address"),
          Map.entry("email_verified", "Whether your email address is verified"),
          Map.entry("gender", "Gender"),
          Map.entry("birthdate", "Date of birth"),
          Map.entry("zoneinfo", "Time zone"),
          Map.entry("locale", "Language and region"),
          Map.entry("phone_number", "Phone number"),
          Map.entry("phone_number_verified", "Whether your phone number is verified"),
          Map.entry("address", "Postal address"),
          Map.entry("updated_at", "When your profile was last updated"),
          Map.entry("nationalities", "Nationalities"),
          Map.entry("place_of_birth", "Place of birth"),
          Map.entry("age_equal_or_over", "Age verification"),
          Map.entry("txn", "Verification transaction reference"));

  /** The scope's description from Authlete if set, else a standard label, else the scope name. */
  public static String scope(String name, String configuredDescription) {
    if (configuredDescription != null && !configuredDescription.isBlank()) {
      return configuredDescription;
    }
    return SCOPES.getOrDefault(name, name);
  }

  /** A label for a claim name (a language tag such as {@code name#ja} is ignored). */
  public static String claim(String name) {
    String base = name.contains("#") ? name.substring(0, name.indexOf('#')) : name;
    return CLAIMS.getOrDefault(base, base);
  }
}

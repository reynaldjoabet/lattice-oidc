package com.lattice.oidc.models;

import java.util.Arrays;
import java.util.Locale;
import java.util.stream.Collectors;

/** Monogram text for apps and people without a logo: up to two initials ("Acme Notes" → "AN"). */
public final class Initials {
  private Initials() {}

  public static String of(String name) {
    if (name == null || name.isBlank()) {
      return "?";
    }
    String initials =
        Arrays.stream(name.trim().split("\\s+"))
            .filter(w -> !w.isEmpty() && Character.isLetterOrDigit(w.codePointAt(0)))
            .limit(2)
            .map(w -> new String(Character.toChars(w.codePointAt(0))))
            .collect(Collectors.joining());
    return (initials.isEmpty() ? name.trim().substring(0, 1) : initials).toUpperCase(Locale.ROOT);
  }
}

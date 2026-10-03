package com.lattice.oidc.common;

import java.util.regex.Pattern;

/**
 * Scrubs secrets from text before it is logged (Authlete error bodies, request descriptions).
 * Covers JSON members and form/query parameters with sensitive names.
 */
public final class Redaction {

  private static final String NAMES =
      "password|client_secret|code|access_token|refresh_token|id_token|id_token_hint|"
          + "assertion|client_assertion|subject_token|actor_token|device_secret|logout_token|"
          + "dpop|token|ticket|request|login_hint_token|tx_code|pre-authorized_code";

  private static final Pattern JSON =
      Pattern.compile("(\"(?:" + NAMES + ")\"\\s*:\\s*)\"[^\"]*\"", Pattern.CASE_INSENSITIVE);
  private static final Pattern FORM =
      Pattern.compile("((?:^|[?&\\s])(?:" + NAMES + ")=)[^&\\s\"]*", Pattern.CASE_INSENSITIVE);

  private Redaction() {}

  public static String redact(String text) {
    if (text == null) {
      return null;
    }
    String out = JSON.matcher(text).replaceAll("$1\"REDACTED\"");
    return FORM.matcher(out).replaceAll("$1REDACTED");
  }
}

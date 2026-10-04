package com.lattice.oidc.common;

/**
 * A short human description of a User-Agent ("Chrome on Windows", "Safari on iPhone"). Good
 * enough to recognise one's own devices; not used for any security decision.
 */
public final class UserAgents {
  private UserAgents() {}

  public static String describe(String userAgent) {
    if (userAgent == null || userAgent.isBlank()) {
      return "Unknown browser";
    }
    String ua = userAgent;
    String browser =
        ua.contains("Edg/") ? "Edge"
            : ua.contains("OPR/") || ua.contains("Opera") ? "Opera"
            : ua.contains("Firefox/") ? "Firefox"
            : ua.contains("Chrome/") || ua.contains("CriOS/") ? "Chrome"
            : ua.contains("Safari/") ? "Safari"
            : null;
    String platform =
        ua.contains("iPhone") ? "iPhone"
            : ua.contains("iPad") ? "iPad"
            : ua.contains("Android") ? "Android"
            : ua.contains("Mac OS X") || ua.contains("Macintosh") ? "macOS"
            : ua.contains("Windows") ? "Windows"
            : ua.contains("CrOS") ? "ChromeOS"
            : ua.contains("Linux") ? "Linux"
            : null;
    if (browser == null && platform == null) {
      return "Unknown browser";
    }
    if (browser == null) {
      return "Browser on " + platform;
    }
    return platform == null ? browser : browser + " on " + platform;
  }
}

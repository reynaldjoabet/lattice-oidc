package com.lattice.oidc.security;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Checks a client's redirect URIs, when they are registered ({@link #problem}) and when a request
 * names one ({@link #matches}).
 *
 * <p>A redirect URI is where the authorization server sends codes and tokens, so a lax check hands
 * them to an attacker. The rules, and the attack each one stops:
 *
 * <ul>
 *   <li><b>Exact match only, no wildcards.</b> A pattern like {@code https://app.example/*} also
 *       matches any page on that site that an attacker can make redirect elsewhere (an open
 *       redirect), and the code follows. OAuth 2.1 and the OAuth security BCP (RFC 9700, section
 *       4.1) require exact matching for this reason.
 *   <li><b>Any port on a loopback IP for {@code http}</b> (RFC 8252, section 7.3). A native app
 *       listens on a port the OS gives it at run time, so it can't register it in advance. Only for
 *       the IP literals {@code 127.0.0.1} and {@code [::1]}: the name {@code localhost} can be pointed
 *       elsewhere by a hosts file or a DNS resolver (RFC 8252, section 8.3).
 *   <li><b>No {@code ..} path segments, encoded or not.</b> A URI that walks out of its registered
 *       path ({@code /cb/..%2F..%2Fopen-redirect}) can match a string check yet reach a different
 *       page once a server normalises it. Double encoding ({@code %252E}) and backslashes count too,
 *       because some servers decode twice or treat {@code \} as {@code /}.
 *   <li><b>No user info</b> ({@code https://app.example@evil.example/}). Browsers and parsers
 *       disagree about which part is the host, and the confusion has been used to steal codes.
 *   <li><b>No OAuth/OIDC response parameters already in the URI</b> ({@code ?code=...}, {@code
 *       #state=...}). The server appends its own; a URI that carries a second copy invites parameter
 *       pollution, where the client reads the attacker's value instead of the server's.
 *   <li><b>No fragment</b> (RFC 6749, section 3.1.2): the server may put the response there.
 *   <li><b>{@code https}, or {@code http} on loopback only.</b> A code sent over plain HTTP can be
 *       read on the network.
 *   <li><b>Private-use schemes must be reverse domain names</b> such as {@code com.example.app:/cb}
 *       (RFC 8252, section 7.1), so that two apps on a device are unlikely to claim the same scheme.
 *       Schemes that run code or read local files ({@code javascript:}, {@code data:}, {@code file:})
 *       are always refused.
 * </ul>
 */
public final class RedirectUris {

  /** Parameters the server adds to the redirect; a registered URI must not already have them. */
  static final Set<String> RESPONSE_PARAMETERS =
      Set.of(
          "code", "state", "iss", "id_token", "access_token", "token_type", "expires_in", "scope",
          "error", "error_description", "error_uri", "session_state", "response");

  private static final Set<String> DANGEROUS_SCHEMES =
      Set.of("javascript", "data", "vbscript", "file", "blob", "about", "filesystem");

  /**
   * A {@code ..} segment between separators: {@code /}, {@code \}, and their percent-encodings, with
   * the dots plain, encoded ({@code %2E}) or double-encoded ({@code %252E}); it may end the path or
   * be followed by {@code ;} or a control character a server might strip.
   */
  private static final Pattern DOT_DOT_SEGMENT =
      Pattern.compile(
          "(?:/|%2f|%5c|\\\\)(?:%2e|%252e|\\.){2}(?:/|%2f|%5c|\\\\|;|%3b|%09|%0a|%0d|%00|$)",
          Pattern.CASE_INSENSITIVE);

  private RedirectUris() {}

  /** Why {@code uri} can't be registered as a redirect URI; empty if it can. */
  public static Optional<String> problem(String uri) {
    if (uri == null || uri.isBlank()) {
      return Optional.of("The redirect URI is empty.");
    }
    URI parsed;
    try {
      parsed = new URI(uri);
    } catch (URISyntaxException e) {
      return Optional.of("The redirect URI is not a valid URI.");
    }
    if (!parsed.isAbsolute()) {
      return Optional.of("The redirect URI must be absolute.");
    }
    if (parsed.getRawFragment() != null) {
      return Optional.of("The redirect URI must not have a fragment.");
    }
    if (uri.contains("*")) {
      return Optional.of("Wildcards are not allowed; register each redirect URI exactly.");
    }
    String scheme = parsed.getScheme().toLowerCase(Locale.ROOT);
    if (DANGEROUS_SCHEMES.contains(scheme)) {
      return Optional.of("The scheme \"" + scheme + "\" is not allowed.");
    }
    if (scheme.equals("http") || scheme.equals("https")) {
      if (parsed.getHost() == null) {
        return Optional.of("The redirect URI has no valid host.");
      }
      if (parsed.getRawUserInfo() != null) {
        return Optional.of("The redirect URI must not contain user info.");
      }
      if (scheme.equals("http") && !isLoopback(parsed.getHost())) {
        return Optional.of("Use https; http is only allowed for loopback addresses.");
      }
    } else if (!scheme.contains(".")) {
      return Optional.of("A private-use scheme must be a reverse domain name, such as com.example.app.");
    }
    String path = parsed.getRawSchemeSpecificPart();
    if (path != null && DOT_DOT_SEGMENT.matcher(path).find()) {
      return Optional.of("The redirect URI must not contain \"..\" path segments.");
    }
    if (hasResponseParameter(parsed.getRawQuery())) {
      return Optional.of("The redirect URI must not already contain OAuth response parameters.");
    }
    return Optional.empty();
  }

  /**
   * Whether {@code requested} is one of the {@code registered} redirect URIs: an exact match, or for
   * {@code http} on a loopback IP, the same URI on another port. A requested URI that would not be
   * accepted for registration never matches.
   */
  public static boolean matches(Collection<String> registered, String requested) {
    if (requested == null || problem(requested).isPresent()) {
      return false;
    }
    for (String candidate : registered) {
      if (candidate.equals(requested) || sameLoopbackUriOnAnotherPort(candidate, requested)) {
        return true;
      }
    }
    return false;
  }

  private static boolean sameLoopbackUriOnAnotherPort(String registered, String requested) {
    try {
      URI a = new URI(registered);
      URI b = new URI(requested);
      return "http".equals(a.getScheme())
          && "http".equals(b.getScheme())
          && isLoopbackIp(a.getHost())
          && a.getHost().equals(b.getHost())
          && a.getRawUserInfo() == null
          && equal(a.getRawPath(), b.getRawPath())
          && equal(a.getRawQuery(), b.getRawQuery());
    } catch (URISyntaxException e) {
      return false;
    }
  }

  private static boolean hasResponseParameter(String rawQuery) {
    if (rawQuery == null || rawQuery.isEmpty()) {
      return false;
    }
    for (String pair : rawQuery.split("&")) {
      int equals = pair.indexOf('=');
      String name = java.net.URLDecoder.decode(
          equals < 0 ? pair : pair.substring(0, equals), java.nio.charset.StandardCharsets.UTF_8);
      if (RESPONSE_PARAMETERS.contains(name.toLowerCase(Locale.ROOT))) {
        return true;
      }
    }
    return false;
  }

  /** 127.0.0.1 or [::1]: IP literals only, never a name that DNS could resolve elsewhere. */
  static boolean isLoopbackIp(String host) {
    return "127.0.0.1".equals(host) || "[::1]".equals(host);
  }

  private static boolean isLoopback(String host) {
    return isLoopbackIp(host) || "localhost".equalsIgnoreCase(host);
  }

  /** Equal, counting a missing component as empty. */
  private static boolean equal(String a, String b) {
    return (a == null ? "" : a).equals(b == null ? "" : b);
  }
}

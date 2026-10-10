package com.lattice.oidc.common;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Whether a browser treats a page as a <i>secure context</i> (W3C Secure Contexts, "Is origin
 * potentially trustworthy?"). WebAuthn, {@code Secure} cookies, {@code crypto.subtle} and service
 * workers only work in one, so this decides, for example, whether to offer passkeys or set {@code
 * Secure} on a cookie in development.
 *
 * <p>A page is a secure context when it is served over {@code https} (or {@code wss}), or from a
 * loopback origin: {@code localhost}, a name under {@code .localhost}, {@code 127.0.0.0/8} or {@code
 * ::1}. Browsers trust loopback because traffic to it never leaves the machine.
 *
 * <p>No DNS lookups: a name only counts as loopback by its form ({@code localhost}), never by what it
 * resolves to, because an attacker can control the resolution of any other name. IP literals are
 * parsed, not resolved.
 *
 * <p>One exception the scheme alone misses: an {@code https} page framed by an {@code http} page is
 * not a secure context (the whole chain of frames must be secure). Browsers send {@code
 * Sec-Fetch-Dest: iframe} and a {@code Referer} for a framed page, which {@link
 * #isSecureContext(URI, String, String)} uses to detect it.
 */
public final class SecureContexts {

  private static final Pattern IPV4 = Pattern.compile("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})");

  private SecureContexts() {}

  /** Whether {@code origin} (a page's URL or origin) is potentially trustworthy. */
  public static boolean isPotentiallyTrustworthy(URI origin) {
    if (origin == null || origin.getScheme() == null) {
      return false;
    }
    String scheme = origin.getScheme().toLowerCase(Locale.ROOT);
    if (scheme.equals("https") || scheme.equals("wss")) {
      return true;
    }
    return (scheme.equals("http") || scheme.equals("ws")) && isLoopbackHost(origin.getHost());
  }

  /**
   * Whether a page at {@code pageUri} is a secure context, given the request's {@code Sec-Fetch-Dest}
   * and {@code Referer} headers (either may be null).
   */
  public static boolean isSecureContext(URI pageUri, String secFetchDest, String referer) {
    if (!isPotentiallyTrustworthy(pageUri)) {
      return false;
    }
    if ("iframe".equalsIgnoreCase(secFetchDest) && referer != null) {
      try {
        return isPotentiallyTrustworthy(new URI(referer));
      } catch (URISyntaxException e) {
        return true; // an unreadable Referer says nothing about the parent
      }
    }
    return true;
  }

  /** {@code localhost}, a name under {@code .localhost}, or a loopback IP literal; never resolved. */
  public static boolean isLoopbackHost(String host) {
    if (host == null || host.isEmpty()) {
      return false;
    }
    String name = host.toLowerCase(Locale.ROOT);
    if (name.endsWith(".")) {
      name = name.substring(0, name.length() - 1);
    }
    if (name.equals("localhost") || name.endsWith(".localhost")) {
      return true;
    }
    var ipv4 = IPV4.matcher(name);
    if (ipv4.matches()) {
      for (int group = 1; group <= 4; group++) {
        if (Integer.parseInt(ipv4.group(group)) > 255) {
          return false;
        }
      }
      return ipv4.group(1).equals("127");
    }
    if (name.startsWith("[") && name.endsWith("]")) {
      name = name.substring(1, name.length() - 1);
    }
    if (name.contains(":") && name.matches("[0-9a-f:.]+")) {
      try {
        // An IPv6 literal (only hex digits, colons and dots): parsed, not looked up.
        return InetAddress.getByName(name).isLoopbackAddress();
      } catch (UnknownHostException e) {
        return false;
      }
    }
    return false;
  }
}

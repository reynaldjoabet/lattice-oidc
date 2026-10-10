package com.lattice.oidc.common;

import java.net.IDN;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Whether a string is a usable email address (RFC 5321 and RFC 5322 syntax, with internationalised
 * domains), before sending mail to it or storing it as a sign-in name.
 *
 * <p>Why not one big regular expression: the parts have different rules, and the classic one-line
 * patterns either reject real addresses or run in exponential time on crafted input (ReDoS). Here
 * each part is checked on its own, with simple patterns:
 *
 * <ul>
 *   <li>Split at the <b>last</b> {@code @}: a quoted local part may itself contain {@code @}
 *       ({@code "a@b"@example.com}).
 *   <li>Local part: at most 64 characters (RFC 5321, 4.5.3.1.1), dot-separated atoms (no leading,
 *       trailing or double dots) or quoted strings. Non-ASCII letters are allowed (RFC 6531).
 *   <li>Domain: converted with IDNA ({@code bücher.example} becomes {@code xn--bcher-kva.example}),
 *       then checked as a host name: labels of letters, digits and hyphens, not starting or ending
 *       with a hyphen, at most 63 characters each and 253 in all. An address literal in brackets
 *       ({@code [192.0.2.1]}, {@code [IPv6:2001:db8::1]}) is allowed only if asked for, since
 *       mail to an IP address is almost always a mistake or an attempt to reach an internal host.
 *   <li>The whole address at most 254 characters (the limit of an SMTP path, RFC 5321 and errata).
 *   <li>No control characters or line breaks anywhere, which could otherwise inject mail headers.
 * </ul>
 */
public final class EmailAddresses {

  public static final int MAX_LOCAL_PART = 64;
  public static final int MAX_DOMAIN = 253;
  public static final int MAX_ADDRESS = 254;

  /** atext of RFC 5322, plus any non-ASCII character (RFC 6531). */
  private static final Pattern ATOM = Pattern.compile("[A-Za-z0-9!#$%&'*+/=?^_`{|}~\\u0080-\\uFFFF-]+");

  /** A quoted string: printable characters other than {@code "} and {@code \}, or a backslash pair. */
  private static final Pattern QUOTED = Pattern.compile("\"(?:[\\x20\\x21\\x23-\\x5B\\x5D-\\x7E\\u0080-\\uFFFF]|\\\\[\\x20-\\x7E])*\"");

  private static final Pattern LABEL = Pattern.compile("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?");
  private static final Pattern IPV4_LITERAL = Pattern.compile("\\[(25[0-5]|2[0-4]\\d|1?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}]");
  private static final Pattern IPV6_LITERAL = Pattern.compile("\\[IPv6:[0-9A-Fa-f:.]{2,45}]");

  private EmailAddresses() {}

  /** Whether {@code address} is a valid email address with a host-name domain. */
  public static boolean isValid(String address) {
    return isValid(address, false);
  }

  /** Whether {@code address} is valid; {@code allowAddressLiterals} also accepts {@code user@[192.0.2.1]}. */
  public static boolean isValid(String address, boolean allowAddressLiterals) {
    if (address == null || address.isEmpty() || address.length() > MAX_ADDRESS) {
      return false;
    }
    for (int i = 0; i < address.length(); i++) {
      char c = address.charAt(i);
      if (c < 0x20 || c == 0x7f) {
        return false;
      }
    }
    int at = address.lastIndexOf('@');
    if (at <= 0 || at == address.length() - 1) {
      return false;
    }
    return isValidLocalPart(address.substring(0, at)) && isValidDomain(address.substring(at + 1), allowAddressLiterals);
  }

  static boolean isValidLocalPart(String local) {
    if (local.length() > MAX_LOCAL_PART || local.startsWith(".") || local.endsWith(".")) {
      return false;
    }
    if (QUOTED.matcher(local).matches()) {
      return true;
    }
    for (String part : local.split("\\.", -1)) {
      if (!ATOM.matcher(part).matches()) {
        return false; // also catches empty parts, from ".."
      }
    }
    return true;
  }

  static boolean isValidDomain(String domain, boolean allowAddressLiterals) {
    if (domain.startsWith("[")) {
      return allowAddressLiterals && (IPV4_LITERAL.matcher(domain).matches() || IPV6_LITERAL.matcher(domain).matches());
    }
    if (domain.endsWith(".")) {
      return false; // valid in DNS, but not in an address, and IDN.toASCII would silently drop it
    }
    String ascii;
    try {
      ascii = IDN.toASCII(domain, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
    } catch (IllegalArgumentException e) {
      return false;
    }
    if (ascii.isEmpty() || ascii.length() > MAX_DOMAIN) {
      return false;
    }
    for (String label : ascii.split("\\.", -1)) {
      if (!LABEL.matcher(label).matches()) {
        return false;
      }
    }
    return true;
  }
}

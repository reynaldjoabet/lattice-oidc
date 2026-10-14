package com.lattice.oidc.common;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Optional;

/**
 * Whether Lattice may send a request to a URL that a client chose: its CIBA client notification
 * endpoint or its back-channel logout URI.
 *
 * <p>Those URLs come from client registration, so whoever registers a client chooses where this
 * server sends requests. Without a check, a client registered with {@code
 * http://169.254.169.254/latest/meta-data/} (a cloud metadata service) or an internal host makes
 * Lattice call it from inside the network (server-side request forgery). The response is never shown
 * to the client, but the request alone can change state on an internal service, and timings reveal
 * what exists.
 *
 * <p>A URL is refused when it is not {@code http(s)}, has no host, or when its host is, or resolves
 * to, an address that is not on the public internet: loopback, unspecified, link-local (which holds
 * the metadata services), private ({@code 10/8}, {@code 172.16/12}, {@code 192.168/16}, {@code
 * fc00::/7}), shared ({@code 100.64/10}), multicast, or {@code 0/8}. Every address the name resolves
 * to is checked, so a name with one public and one private address is refused.
 *
 * <p><b>Limit.</b> The HTTP client resolves the name again when it connects, so a name whose answer
 * changes between the two lookups (DNS rebinding) can still reach a private address. Closing that
 * needs the connection pinned to the checked address, or an egress proxy that applies the same rule;
 * where the network allows it, the egress firewall is the stronger control.
 *
 * <p>{@code lattice.outbound.allow-private-addresses = true} turns the address check off (the scheme
 * check stays), for development and tests where the client runs on the same machine.
 */
public final class OutboundUrls {

  private OutboundUrls() {}

  /** Why Lattice must not call {@code url}, or empty if it may. Resolves the host (blocking). */
  public static Optional<String> problem(String url, boolean allowPrivateAddresses) {
    URI uri;
    try {
      uri = URI.create(url);
    } catch (IllegalArgumentException | NullPointerException e) {
      return Optional.of("not a valid URL");
    }
    String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
    if (!scheme.equals("https") && !scheme.equals("http")) {
      return Optional.of("not an http(s) URL");
    }
    if (uri.getHost() == null || uri.getHost().isEmpty()) {
      return Optional.of("no host");
    }
    if (uri.getUserInfo() != null) {
      return Optional.of("credentials in the URL");
    }
    if (allowPrivateAddresses) {
      return Optional.empty();
    }
    InetAddress[] addresses;
    try {
      addresses = InetAddress.getAllByName(uri.getHost());
    } catch (UnknownHostException e) {
      return Optional.of("the host does not resolve");
    }
    for (InetAddress address : addresses) {
      if (!isPublic(address)) {
        return Optional.of("the host is, or resolves to, a non-public address (" + address.getHostAddress() + ")");
      }
    }
    return Optional.empty();
  }

  /** Whether {@code address} is on the public internet (see the class description). */
  static boolean isPublic(InetAddress address) {
    if (address.isLoopbackAddress()
        || address.isAnyLocalAddress()
        || address.isLinkLocalAddress()
        || address.isSiteLocalAddress()
        || address.isMulticastAddress()) {
      return false;
    }
    byte[] b = address.getAddress();
    if (address instanceof Inet4Address) {
      int first = b[0] & 0xff;
      int second = b[1] & 0xff;
      return first != 0 // 0.0.0.0/8, "this network"
          && !(first == 100 && second >= 64 && second <= 127) // 100.64.0.0/10, carrier-grade NAT
          && !(first == 192 && second == 0 && (b[2] & 0xff) == 0) // 192.0.0.0/24, IETF protocol assignments
          && first < 240; // 240.0.0.0/4, reserved, and the broadcast address
    }
    if (address instanceof Inet6Address) {
      if ((b[0] & 0xfe) == 0xfc) { // fc00::/7, unique local
        return false;
      }
      if (isMappedOrCompatibleIpv4(b)) { // ::ffff:a.b.c.d and ::a.b.c.d carry an IPv4 address
        try {
          return isPublic(InetAddress.getByAddress(new byte[] {b[12], b[13], b[14], b[15]}));
        } catch (UnknownHostException e) {
          return false;
        }
      }
    }
    return true;
  }

  private static boolean isMappedOrCompatibleIpv4(byte[] b) {
    for (int i = 0; i < 10; i++) {
      if (b[i] != 0) {
        return false;
      }
    }
    return (b[10] == (byte) 0xff && b[11] == (byte) 0xff) || (b[10] == 0 && b[11] == 0);
  }
}

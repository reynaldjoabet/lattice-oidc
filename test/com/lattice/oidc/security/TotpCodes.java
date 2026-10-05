package com.lattice.oidc.security;

/** Test access to the authenticator-code helpers, which stay package-private in {@link Totp}. */
public final class TotpCodes {
  private TotpCodes() {}

  /** The code an authenticator app shows for {@code secret} at time step {@code step}. */
  public static String at(String secret, long step) {
    return Totp.code(secret, step);
  }

  public static String base32(byte[] bytes) {
    return Totp.base32(bytes);
  }
}

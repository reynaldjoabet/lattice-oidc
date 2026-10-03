package com.lattice.oidc.models;

import java.util.List;
import java.util.Optional;

/**
 * A CIBA request waiting for the end-user's decision on Lattice's own approval page
 * ({@code lattice.ciba.mode = builtin}): which app asks, its binding message and what it gets.
 */
public record CibaApproval(
    String id,
    String clientName,
    Optional<String> bindingMessage,
    List<String> permissions,
    long expiresAt) {

  public boolean expired(long nowSeconds) {
    return nowSeconds >= expiresAt;
  }

  /** "1:52" style countdown text for the expiry pill. */
  public String remaining() {
    long seconds = Math.max(0, expiresAt - System.currentTimeMillis() / 1000L);
    return seconds / 60 + ":" + String.format("%02d", seconds % 60);
  }
}

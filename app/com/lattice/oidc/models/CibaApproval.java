package com.lattice.oidc.models;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A CIBA request waiting for the end-user's decision on Lattice's own approval page
 * ({@code lattice.ciba.mode = builtin}): which app asks, its binding message, what it gets and,
 * for a payment (RFC 9396 {@code authorization_details} of type {@code payment_initiation}), the
 * payment itself.
 */
public record CibaApproval(
    String id,
    String clientName,
    Optional<String> bindingMessage,
    List<String> permissions,
    long expiresAt,
    Optional<Payment> payment,
    String authorizationDetails) {

  /** A payment to approve, as the request described it. Missing fields are empty. */
  public record Payment(String amount, String currency, String payee, String payeeAccount, String reference) {

    @SuppressWarnings("unchecked")
    static Optional<Payment> from(List<Object> details) {
      for (Object element : details) {
        if (element instanceof Map<?, ?> map && "payment_initiation".equals(map.get("type"))) {
          Map<String, Object> amount =
              map.get("instructedAmount") instanceof Map<?, ?> found ? (Map<String, Object>) found : Map.of();
          Map<String, Object> account =
              map.get("creditorAccount") instanceof Map<?, ?> found ? (Map<String, Object>) found : Map.of();
          return Optional.of(
              new Payment(
                  text(amount.get("amount")),
                  text(amount.get("currency")),
                  text(map.get("creditorName")),
                  text(account.containsKey("iban") ? account.get("iban") : account.get("accountNumber")),
                  text(map.get("remittanceInformationUnstructured"))));
        }
      }
      return Optional.empty();
    }

    private static String text(Object value) {
      return value == null ? "" : value.toString();
    }
  }

  public static CibaApproval of(
      String id,
      String clientName,
      Optional<String> bindingMessage,
      List<String> permissions,
      long expiresAt,
      List<Object> details,
      String detailsJson) {
    return new CibaApproval(
        id, clientName, bindingMessage, permissions, expiresAt, Payment.from(details), detailsJson);
  }

  public boolean expired(long nowSeconds) {
    return nowSeconds >= expiresAt;
  }

  /** "1:52" style countdown text for the expiry pill. */
  public String remaining() {
    long seconds = Math.max(0, expiresAt - System.currentTimeMillis() / 1000L);
    return seconds / 60 + ":" + String.format("%02d", seconds % 60);
  }

  /**
   * What a passkey approval signs: the request id, the app, the binding message and the
   * authorization details, exactly as shown.
   */
  public String signedContent() {
    return String.join("\n", id, clientName, bindingMessage.orElse(""), authorizationDetails);
  }
}

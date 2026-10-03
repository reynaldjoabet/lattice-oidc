package com.lattice.oidc.handlers;

/** A credential request this issuer rejects, carrying its OID4VCI error code. */
public final class CredentialRequestException extends Exception {
  private static final long serialVersionUID = 1L;

  private final String errorCode;

  public CredentialRequestException(String errorCode, String message) {
    super(message);
    this.errorCode = errorCode;
  }

  public String errorCode() {
    return errorCode;
  }

  static CredentialRequestException invalidRequest(String message) {
    return new CredentialRequestException("invalid_credential_request", message);
  }
}

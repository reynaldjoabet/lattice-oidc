package com.lattice.oidc.http;

import play.mvc.Result;

/** Aborts request processing with a ready-made HTTP response. */
public final class WebException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  private final transient Result result;

  public WebException(Result result) {
    super(null, null, false, false);
    this.result = result;
  }

  public Result result() {
    return result;
  }
}

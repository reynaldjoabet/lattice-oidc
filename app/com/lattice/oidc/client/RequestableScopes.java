
package com.lattice.oidc.client;

import java.io.Serializable;

/** Request/response body of the requestable_scopes APIs. */
class RequestableScopes implements Serializable {
  private static final long serialVersionUID = 1L;

  private String[] requestableScopes;

  public String[] getRequestableScopes() {
    return requestableScopes;
  }

  public RequestableScopes setRequestableScopes(String[] requestableScopes) {
    this.requestableScopes = requestableScopes;
    return this;
  }
}

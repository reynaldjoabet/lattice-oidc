package com.lattice.oidc.controllers;

import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.security.ObbCertValidator;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import jakarta.inject.Inject;
import play.mvc.Controller;
import play.mvc.Http;
import play.mvc.Result;

/** Diagnostics for deployments behind proxies; disabled unless lattice.test-endpoints.enabled. */
public final class TestController extends Controller {

  private final LatticeConfig config;
  private final Requests requests;
  private final ObbCertValidator obbCerts;

  @Inject
  public TestController(LatticeConfig config, Requests requests, ObbCertValidator obbCerts) {
    this.config = config;
    this.requests = requests;
    this.obbCerts = obbCerts;
  }

  /**
   * Returns the HTTP headers that this endpoint received, in JSON format (Authorization and Cookie
   * are redacted). Useful to check what a reverse proxy forwards.
   */
  public Result headers(Http.Request request) {
    if (!config.testEndpointsEnabled()) {
      return notFound();
    }
    Map<String, Object> out = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    request
        .getHeaders()
        .asMap()
        .forEach(
            (name, values) -> {
              boolean secret = name.equalsIgnoreCase("Authorization") || name.equalsIgnoreCase("Cookie");
              List<String> shown = secret ? List.of("<redacted>") : values;
              out.put(name, shown.size() == 1 ? shown.get(0) : shown);
            });
    return ok(Jsons.pretty(out)).as("application/json");
  }

  /**
   * Checks whether the root certificate of the certificate chain that consists of the presented
   * client certificate and intermediate certificates is a certificate issued by the authority of
   * Open Banking Brasil. The result is returned in JSON format.
   *
   * <p>Example, assuming certificates.pem includes a client certificate and intermediate certificates:
   * <pre>$ curl -k --key private.pem --cert certificates.pem https://example/api/test/obb</pre>
   */
  public Result obb(Http.Request request) {
    if (!config.testEndpointsEnabled()) {
      return notFound();
    }
    try {
      obbCerts.validate(requests.clientCertificateChain(request));
      return ok(Jsons.pretty(Map.of("result", "succeeded"))).as("application/json");
    } catch (GeneralSecurityException e) {
      return ok(Jsons.pretty(Map.of("result", "failed", "error_message", String.valueOf(e.getMessage()))))
          .as("application/json");
    }
  }
}

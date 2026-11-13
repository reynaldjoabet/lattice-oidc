package com.lattice.oidc.security;

import com.lattice.oidc.client.ServerMetadata;
import com.lattice.oidc.common.Responses;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.typesafe.config.Config;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.mvc.Result;

/**
 * The audience rule for JWT client authentication (RFC 10070, updating RFC 7523 and RFC 9126): a
 * {@code client_assertion} must name this server's issuer identifier as its only {@code aud} value.
 * The token endpoint URL, the PAR endpoint URL or a list with other values are refused.
 *
 * <p>This closes the audience-injection attack: an assertion a client made for another server, or
 * one an attacker got a client to sign for an endpoint URL it controls, can't be replayed here.
 * Authlete still verifies the signature, expiry and replay; this only adds the stricter audience
 * check before the request reaches it.
 *
 * <p>Only client authentication is affected. The {@code assertion} of the JWT authorization grant
 * (RFC 7523 section 2.1) may still name the token endpoint URL. The {@code typ} header ({@code
 * client-authentication+jwt}) isn't required: RFC 10070 recommends against refusing assertions
 * without it.
 *
 * <p>{@code lattice.client-assertion.strict-audience = false} logs the refusals instead, for a
 * migration period while clients move from the token endpoint URL to the issuer.
 */
@Singleton
public final class ClientAssertionAudience {

  private static final Logger LOG = LoggerFactory.getLogger(ClientAssertionAudience.class);

  static final String JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

  private final ServerMetadata server;
  private final boolean strict;

  @Inject
  public ClientAssertionAudience(ServerMetadata server, Config config) {
    this.server = server;
    this.strict = config.getBoolean("lattice.client-assertion.strict-audience");
  }

  /**
   * The error response when the request carries a JWT client assertion whose audience isn't exactly
   * this server's issuer; empty when there is none, or it is acceptable.
   */
  public Optional<Result> refuse(Map<String, String[]> form) {
    String assertion = first(form, "client_assertion");
    if (assertion == null || !JWT_BEARER.equals(first(form, "client_assertion_type"))) {
      return Optional.empty();
    }
    Optional<String> problem = problem(assertion, server.issuer());
    if (problem.isEmpty()) {
      return Optional.empty();
    }
    String clientId = first(form, "client_id");
    if (!strict) {
      LOG.warn(
          "Accepted a client assertion from client {} although {} (strict-audience is off)",
          clientId,
          problem.get());
      return Optional.empty();
    }
    LOG.info("Refused a client assertion from client {}: {}", clientId, problem.get());
    return Optional.of(
        Responses.unauthorized(
            Responses.error(
                "invalid_client",
                "The client assertion's audience must be the issuer identifier, and only it."),
            null,
            null));
  }

  /**
   * Why the assertion's audience isn't acceptable, or empty if it is. Assertions that aren't signed
   * JWTs are left to Authlete, which refuses them.
   */
  static Optional<String> problem(String assertion, String issuer) {
    JWT jwt;
    List<String> audience;
    try {
      jwt = JWTParser.parse(assertion);
      if (!(jwt instanceof SignedJWT)) {
        return Optional.empty();
      }
      audience = jwt.getJWTClaimsSet().getAudience();
    } catch (ParseException e) {
      return Optional.empty();
    }
    if (audience.size() == 1 && audience.get(0).equals(issuer)) {
      return Optional.empty();
    }
    return Optional.of(
        audience.isEmpty()
            ? "it has no audience"
            : "its audience is " + audience + ", not exactly [" + issuer + "]");
  }

  private static String first(Map<String, String[]> form, String name) {
    String[] values = form.get(name);
    return values == null || values.length == 0 ? null : values[0];
  }
}

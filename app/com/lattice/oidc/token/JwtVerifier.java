package com.lattice.oidc.token;

import com.lattice.oidc.config.LatticeConfig;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.net.MalformedURLException;
import java.net.URI;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.inject.Inject;
import javax.inject.Singleton;

/**
 * Verifies signed JWTs issued by this server (keys from Authlete) or by a configured trusted issuer
 * (keys from its JWKS URI, cached and rate-limited by Nimbus). Unsigned and encrypted JWTs are
 * rejected.
 */
@Singleton
public final class JwtVerifier {

  public static final class InvalidJwtException extends Exception {
    private static final long serialVersionUID = 1L;

    InvalidJwtException(String message) {
      super(message);
    }
  }

  private static final Set<JWSAlgorithm> ALGORITHMS =
      Set.of(
          JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
          JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512,
          JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512,
          JWSAlgorithm.EdDSA, JWSAlgorithm.Ed25519);

  private final ServerMetadata server;
  private final Map<String, JWKSource<SecurityContext>> trusted = new ConcurrentHashMap<>();

  @Inject
  public JwtVerifier(ServerMetadata server, LatticeConfig config) throws MalformedURLException {
    this.server = server;
    for (LatticeConfig.TrustedIssuer t : config.trustedIssuers()) {
      trusted.put(
          t.issuer(), JWKSourceBuilder.create(URI.create(t.jwksUri()).toURL()).retrying(true).build());
    }
  }

  /**
   * Verifies signature, issuer trust, {@code exp}/{@code nbf} (unless {@code allowExpired}) and,
   * when given, that {@code aud} contains one of {@code audiences}.
   */
  public JWTClaimsSet verify(String token, Set<String> audiences, boolean allowExpired)
      throws InvalidJwtException {
    JWT jwt;
    try {
      jwt = JWTParser.parse(token);
    } catch (java.text.ParseException e) {
      throw new InvalidJwtException("The token is not a JWT.");
    }
    if (!(jwt instanceof SignedJWT signed)) {
      throw new InvalidJwtException("The JWT must be signed (JWS) and not encrypted.");
    }
    String issuer;
    try {
      issuer = signed.getJWTClaimsSet().getIssuer();
    } catch (java.text.ParseException e) {
      throw new InvalidJwtException("The JWT payload is malformed.");
    }
    if (issuer == null) {
      throw new InvalidJwtException("The JWT has no 'iss' claim.");
    }
    JWKSource<SecurityContext> keys = keysFor(issuer).orElseThrow(
        () -> new InvalidJwtException("The issuer '" + issuer + "' is not trusted."));

    DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
    processor.setJWSKeySelector(new JWSVerificationKeySelector<>(ALGORITHMS, keys));
    Set<String> required = new HashSet<>(Set.of("iss", "sub"));
    if (!allowExpired) {
      required.add("exp");
    }
    processor.setJWTClaimsSetVerifier(
        allowExpired
            ? (claims, ctx) -> {}
            : new DefaultJWTClaimsVerifier<>(
                null, new JWTClaimsSet.Builder().issuer(issuer).build(), required));
    try {
      JWTClaimsSet claims = processor.process(signed, null);
      if (audiences != null
          && !audiences.isEmpty()
          && (claims.getAudience() == null
              || claims.getAudience().stream().noneMatch(audiences::contains))) {
        throw new InvalidJwtException("The JWT audience does not include this server.");
      }
      if (claims.getSubject() == null) {
        throw new InvalidJwtException("The JWT has no 'sub' claim.");
      }
      return claims;
    } catch (InvalidJwtException e) {
      throw e;
    } catch (Exception e) {
      throw new InvalidJwtException("JWT verification failed: " + e.getMessage());
    }
  }

  private Optional<JWKSource<SecurityContext>> keysFor(String issuer) {
    if (issuer.equals(server.issuer())) {
      return Optional.of(new ImmutableJWKSet<>(server.jwks()));
    }
    return Optional.ofNullable(trusted.get(issuer));
  }
}

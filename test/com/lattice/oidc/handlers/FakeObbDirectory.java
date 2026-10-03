package com.lattice.oidc.handlers;

import com.lattice.oidc.common.Jsons;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A stand-in for the Open Banking Brasil directory: serves its JWK Set on a local port and signs
 * software statements. Point {@code lattice.obb.directory-jwks-uri} at {@link #jwksUri}.
 */
public final class FakeObbDirectory implements AutoCloseable {

  public static final String SOFTWARE_JWKS_URI =
      "https://keystore.sandbox.directory.openbankingbrasil.org.br/org-1/software-1/application.jwks";
  public static final String REDIRECT_URI = "https://tpp.example/cb";

  private final HttpServer server;
  private final RSAKey key;
  public final String jwksUri;

  public FakeObbDirectory() {
    try {
      key = new RSAKeyGenerator(2048).keyID("directory").generate();
      server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    } catch (JOSEException e) {
      throw new IllegalStateException(e);
    }
    jwksUri = "http://127.0.0.1:" + server.getAddress().getPort() + "/openbanking.jwks";
    server.createContext(
        "/openbanking.jwks",
        ex -> {
          byte[] body = new JWKSet(key.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);
          ex.getResponseHeaders().set("Content-Type", "application/json");
          ex.sendResponseHeaders(200, body.length);
          ex.getResponseBody().write(body);
          ex.close();
        });
    server.start();
  }

  /** Claims of a valid DADOS (data) software statement issued now. */
  public static Map<String, Object> claims() {
    Map<String, Object> c = new LinkedHashMap<>();
    c.put("software_id", "software-1");
    c.put("org_id", "org-1");
    c.put("software_client_name", "Example TPP");
    c.put("software_jwks_uri", SOFTWARE_JWKS_URI);
    c.put("software_redirect_uris", List.of(REDIRECT_URI));
    c.put("software_roles", List.of("DADOS"));
    c.put("software_environment", "sandbox");
    return c;
  }

  /** Signs {@code claims} as the directory, with {@code alg} and an {@code iat} of {@code iat}. */
  public String sign(Map<String, Object> claims, JWSAlgorithm alg, Date iat) {
    JWTClaimsSet.Builder b = new JWTClaimsSet.Builder().issuer("Open Banking Brasil sandbox SSA issuer");
    claims.forEach(b::claim);
    b.issueTime(iat);
    try {
      SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(alg).keyID(key.getKeyID()).build(), b.build());
      jwt.sign(new RSASSASigner(key));
      return jwt.serialize();
    } catch (JOSEException e) {
      throw new IllegalStateException(e);
    }
  }

  public String sign(Map<String, Object> claims) {
    return sign(claims, JWSAlgorithm.PS256, new Date());
  }

  /** A registration request body that matches {@code statement}. */
  public static Map<String, Object> request(String statement) {
    Map<String, Object> r = new LinkedHashMap<>();
    r.put("software_statement", statement);
    r.put("jwks_uri", SOFTWARE_JWKS_URI);
    r.put("redirect_uris", List.of(REDIRECT_URI));
    r.put("token_endpoint_auth_method", "private_key_jwt");
    return r;
  }

  public String validRequestBody() {
    return Jsons.write(request(sign(claims())));
  }

  @Override
  public void close() {
    server.stop(0);
  }
}

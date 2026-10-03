package com.lattice.oidc.handlers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A minimal upstream OpenID Provider on a local port, for identity brokering tests: discovery,
 * JWKS, a token endpoint that returns an RS256 ID token, and UserInfo. Tests set {@link #nonce}
 * (from the redirect Lattice produced) and may tamper with {@link #idTokenSubject} or {@link
 * #userInfoSubject} to simulate a misbehaving provider.
 */
public final class FakeUpstreamProvider implements AutoCloseable {

  public static final String CLIENT_ID = "lattice-at-upstream";

  private final HttpServer server;
  private final RSAKey key;
  public final String issuer;
  public final AtomicInteger tokenRequests = new AtomicInteger();

  public volatile String nonce;
  public volatile String idTokenSubject = "alice";
  public volatile String userInfoSubject = "alice";

  public FakeUpstreamProvider() throws IOException, JOSEException {
    key = new RSAKeyGenerator(2048).keyID("k1").generate();
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    issuer = "http://127.0.0.1:" + server.getAddress().getPort();
    server.createContext("/.well-known/openid-configuration", ex -> json(ex, discovery()));
    server.createContext("/jwks", ex -> json(ex, new JWKSet(key.toPublicJWK()).toString()));
    server.createContext("/token", this::token);
    server.createContext(
        "/userinfo",
        ex ->
            json(
                ex,
                "{\"sub\":\"" + userInfoSubject + "\",\"name\":\"Alice Upstream\","
                    + "\"email\":\"alice@upstream.example\"}"));
    server.start();
  }

  private String discovery() {
    return "{\"issuer\":\"" + issuer + "\","
        + "\"authorization_endpoint\":\"" + issuer + "/authorize\","
        + "\"token_endpoint\":\"" + issuer + "/token\","
        + "\"userinfo_endpoint\":\"" + issuer + "/userinfo\","
        + "\"jwks_uri\":\"" + issuer + "/jwks\","
        + "\"response_types_supported\":[\"code\"],"
        + "\"subject_types_supported\":[\"public\"],"
        + "\"id_token_signing_alg_values_supported\":[\"RS256\"]}";
  }

  private void token(HttpExchange ex) throws IOException {
    tokenRequests.incrementAndGet();
    ex.getRequestBody().readAllBytes();
    try {
      Date now = new Date();
      SignedJWT idToken =
          new SignedJWT(
              new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
              new JWTClaimsSet.Builder()
                  .issuer(issuer)
                  .subject(idTokenSubject)
                  .audience(CLIENT_ID)
                  .issueTime(now)
                  .expirationTime(new Date(now.getTime() + 300_000))
                  .claim("nonce", nonce)
                  .build());
      idToken.sign(new RSASSASigner(key));
      json(
          ex,
          "{\"access_token\":\"upstream-at\",\"token_type\":\"Bearer\",\"expires_in\":300,"
              + "\"id_token\":\"" + idToken.serialize() + "\"}");
    } catch (JOSEException e) {
      throw new IOException(e);
    }
  }

  /**
   * A JWT signed with this provider's key. {@code iss} need not be this provider's issuer, so a
   * second instance can forge tokens that claim to come from the first.
   */
  public String jwt(String iss, String sub, String aud) {
    Date now = new Date();
    JWTClaimsSet.Builder claims =
        new JWTClaimsSet.Builder()
            .issuer(iss)
            .subject(sub)
            .issueTime(now)
            .expirationTime(new Date(now.getTime() + 300_000));
    if (aud != null) {
      claims.audience(aud);
    }
    try {
      SignedJWT jwt =
          new SignedJWT(
              new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims.build());
      jwt.sign(new RSASSASigner(key));
      return jwt.serialize();
    } catch (JOSEException e) {
      throw new IllegalStateException(e);
    }
  }

  public String jwksUri() {
    return issuer + "/jwks";
  }

  private static void json(HttpExchange ex, String body) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    ex.getResponseHeaders().set("Content-Type", "application/json");
    ex.sendResponseHeaders(200, bytes.length);
    ex.getResponseBody().write(bytes);
    ex.close();
  }

  /** Writes an identity providers file that registers this provider under {@code id}. */
  public Path configFile(String id, String redirectUri) throws IOException {
    Path file = Files.createTempFile("identity-providers", ".json");
    file.toFile().deleteOnExit();
    Files.writeString(
        file,
        "{\"federations\":[{\"id\":\"" + id + "\","
            + "\"server\":{\"name\":\"Upstream\",\"issuer\":\"" + issuer + "\"},"
            + "\"client\":{\"clientId\":\"" + CLIENT_ID + "\",\"clientSecret\":\"s3cret\","
            + "\"redirectUri\":\"" + redirectUri + "\"}}]}");
    return file;
  }

  @Override
  public void close() {
    server.stop(0);
  }
}

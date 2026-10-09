package com.lattice.oidc.handlers;

import com.lattice.oidc.common.JsonHelpers;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.common.WebException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/**
 * Dynamic client registration rules of Open Banking Brasil.
 *
 * <p>Verifies the software statement signed by the directory (PS256, issued within 5 minutes),
 * cross-checks it against the request ({@code jwks_uri}, {@code redirect_uris}, scopes allowed by
 * the {@code software_roles}, ...), applies the FAPI security profile (PS256, RSA-OAEP, A256GCM,
 * certificate-bound tokens, signed request objects) and returns the merged client metadata to
 * register with Authlete.
 *
 * @see <a href="https://openbanking-brasil.github.io/specs-seguranca/open-banking-brasil-dynamic-client-registration-1_ID1.html">Open Banking Brasil Financial-grade API Dynamic Client Registration 1.0</a>
 */
@Singleton
public final class ObbDcrHandler {

  private static final Set<String> AUTH_METHODS =
      Set.of("private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth");
  private static final List<String> SAN_METADATA =
      List.of(
          "tls_client_auth_san_dns",
          "tls_client_auth_san_uri",
          "tls_client_auth_san_ip",
          "tls_client_auth_san_email");
  private static final List<String> JWS_ALG_METADATA =
      List.of(
          "id_token_signed_response_alg",
          "userinfo_signed_response_alg",
          "request_object_signing_alg",
          "token_endpoint_auth_signing_alg",
          "backchannel_authentication_request_signing_alg",
          "authorization_signed_response_alg");
  private static final List<String> JWE_ALG_METADATA =
      List.of(
          "id_token_encrypted_response_alg",
          "userinfo_encrypted_response_alg",
          "request_object_encryption_alg",
          "authorization_encrypted_response_alg");
  private static final List<String> JWE_ENC_METADATA =
      List.of(
          "id_token_encrypted_response_enc",
          "userinfo_encrypted_response_enc",
          "request_object_encryption_enc",
          "authorization_encrypted_response_enc");
  private static final Set<String> RECOGNIZED =
      Set.of(
          "redirect_uris", "response_types", "grant_types", "application_type", "contacts",
          "client_name", "logo_uri", "client_uri", "policy_uri", "tos_uri", "jwks_uri",
          "sector_identifier_uri", "subject_type", "id_token_signed_response_alg",
          "id_token_encrypted_response_alg", "id_token_encrypted_response_enc",
          "userinfo_signed_response_alg", "userinfo_encrypted_response_alg",
          "userinfo_encrypted_response_enc", "request_object_signing_alg",
          "request_object_encryption_alg", "request_object_encryption_enc",
          "token_endpoint_auth_method", "token_endpoint_auth_signing_alg", "default_max_age",
          "require_auth_time", "default_acr_values", "initiate_login_uri", "request_uris", "scope",
          "software_id", "software_version", "client_id", "client_secret",
          "tls_client_certificate_bound_access_tokens", "tls_client_auth_subject_dn",
          "backchannel_token_delivery_mode", "backchannel_client_notification_endpoint",
          "backchannel_authentication_request_signing_alg", "backchannel_user_code_parameter",
          "require_signed_request_object", "authorization_signed_response_alg",
          "authorization_encrypted_response_alg", "authorization_encrypted_response_enc",
          "require_pushed_authorization_requests", "authorization_details_types",
          "software_client_name", "software_client_id", "software_tos_uri",
          "software_client_description", "software_jwks_uri", "software_policy_uri",
          "software_client_uri", "software_jwks_inactive_uri",
          "software_jwks_transport_inactive_uri", "software_logo_uri", "org_id", "org_number",
          "software_environment", "software_roles", "org_name");
  private static final Map<String, Set<String>> ROLE_SCOPES =
      Map.of(
          "DADOS",
              Set.of(
                  "openid", "accounts", "credit-cards-accounts", "consents", "customers",
                  "invoice-financings", "financings", "loans", "unarranged-accounts-overdraft",
                  "resources"),
          "PAGTO", Set.of("openid", "payments", "consents", "resources"),
          "CONTA", Set.of("openid"),
          "CCORR", Set.of("openid"));

  private static final String SANDBOX_JWKS =
      "https://keystore.sandbox.directory.openbankingbrasil.org.br/openbanking.jwks";
  private static final String PRODUCTION_JWKS =
      "https://keystore.directory.openbankingbrasil.org.br/openbanking.jwks";

  private final LatticeConfig config;

  @Inject
  public ObbDcrHandler(LatticeConfig config) {
    this.config = config;
  }

  /** Whether the body carries a software statement whose JWKS is hosted by the OBB directory. */
  public static boolean isObbRequest(String body) {
    try {
      Object statement = JsonHelpers.readMap(body).get("software_statement");
      if (!(statement instanceof String s)) {
        return false;
      }
      String uri = SignedJWT.parse(s).getJWTClaimsSet().getStringClaim("software_jwks_uri");
      return uri != null && uri.contains("openbankingbrasil");
    } catch (Exception e) {
      return false;
    }
  }

  /** Validates the request and returns the client metadata JSON to register. */
  public String process(String body) {
    Map<String, Object> params;
    try {
      params = JsonHelpers.readMap(body);
    } catch (RuntimeException e) {
      throw error("invalid_request", "The request body is not a JSON object.");
    }
    SignedJWT statement = softwareStatement(params);
    Map<String, Object> claims;
    try {
      claims = statement.getJWTClaimsSet().getClaims();
    } catch (java.text.ParseException e) {
      throw error("invalid_software_statement", "The software statement payload is malformed.");
    }
    validate(params, claims);
    return JsonHelpers.write(merge(params, claims));
  }

  private SignedJWT softwareStatement(Map<String, Object> params) {
    if (!(params.get("software_statement") instanceof String value)) {
      throw error("invalid_request", "'software_statement' is missing or not a string.");
    }
    SignedJWT statement;
    try {
      statement = SignedJWT.parse(value);
    } catch (java.text.ParseException e) {
      throw error("invalid_software_statement", "The software statement is not a signed JWT.");
    }
    if (!JWSAlgorithm.PS256.equals(statement.getHeader().getAlgorithm())) {
      throw error("invalid_software_statement", "The software statement must be signed with PS256.");
    }
    JWKSet jwks;
    String location = directoryJwks(statement);
    try {
      jwks = JWKSet.load(URI.create(location).toURL(), 10_000, 10_000, 1_000_000);
    } catch (Exception e) {
      throw error("server_error", "Failed to fetch the directory JWK Set.", 500);
    }
    List<JWK> keys = new JWKSelector(JWKMatcher.forJWSHeader(statement.getHeader())).select(jwks);
    if (keys.size() != 1 || !(keys.get(0) instanceof RSAKey rsa)) {
      throw error(
          "invalid_software_statement",
          "Exactly one directory key must match the software statement header.");
    }
    try {
      if (!statement.verify(new RSASSAVerifier(rsa.toRSAPublicKey()))) {
        throw error("invalid_software_statement", "The software statement signature is invalid.");
      }
    } catch (com.nimbusds.jose.JOSEException e) {
      throw error("invalid_software_statement", "The software statement signature is invalid.");
    }
    return statement;
  }

  private String directoryJwks(SignedJWT statement) {
    if (config.obbDirectoryJwksUri().isPresent()) {
      return config.obbDirectoryJwksUri().get();
    }
    try {
      return "production".equals(statement.getJWTClaimsSet().getStringClaim("software_environment"))
          ? PRODUCTION_JWKS
          : SANDBOX_JWKS;
    } catch (java.text.ParseException e) {
      return SANDBOX_JWKS;
    }
  }

  private void validate(Map<String, Object> request, Map<String, Object> statement) {
    if (!(statement.get("iat") instanceof Date iat)) {
      throw error("invalid_software_statement", "The software statement has no 'iat'.");
    }
    long age = System.currentTimeMillis() - iat.getTime();
    if (age < 0 || age > 300_000L) {
      throw error(
          "invalid_software_statement", "The software statement must be issued within 5 minutes.");
    }
    if (request.containsKey("jwks") || statement.containsKey("jwks")) {
      throw error("invalid_client_metadata", "'jwks' is not allowed; use 'jwks_uri'.");
    }
    Object jwksUri = request.get("jwks_uri");
    if (jwksUri == null || !jwksUri.equals(statement.get("software_jwks_uri"))) {
      throw error("invalid_client_metadata", "'jwks_uri' must equal 'software_jwks_uri'.");
    }
    List<String> redirectUris = strings(request, "redirect_uris", "the request body");
    Set<String> allowed = new HashSet<>(strings(statement, "software_redirect_uris", "the software statement"));
    for (int i = 0; i < redirectUris.size(); i++) {
      if (!allowed.contains(redirectUris.get(i))) {
        throw error(
            "invalid_redirect_uri",
            "redirect_uris[" + i + "] is not listed in the software statement.");
      }
    }
    String method = string(request, statement, "token_endpoint_auth_method");
    if (method == null || !AUTH_METHODS.contains(method)) {
      throw error("invalid_client_metadata", "'token_endpoint_auth_method' is missing or not allowed.");
    }
    List<String> roles = strings(statement, "software_roles", "the software statement");
    String scope = string(request, statement, "scope");
    if (scope != null && !scope.isBlank()) {
      for (String s : scope.trim().split(" +")) {
        if (roles.stream().noneMatch(r -> allowedScopes(r).contains(s))) {
          throw error("invalid_client_metadata", "The scope '" + s + "' is not allowed by any role.");
        }
      }
    }
    for (String m : SAN_METADATA) {
      if (request.containsKey(m) || statement.containsKey(m)) {
        throw error("invalid_client_metadata", "'" + m + "' is not allowed.");
      }
    }
    requireValue(request, statement, JWS_ALG_METADATA, "PS256");
    requireValue(request, statement, JWE_ALG_METADATA, "RSA-OAEP");
    requireValue(request, statement, JWE_ENC_METADATA, "A256GCM");
  }

  private Map<String, Object> merge(Map<String, Object> request, Map<String, Object> statement) {
    Map<String, Object> merged = new HashMap<>();
    for (String m : RECOGNIZED) {
      Object v = statement.containsKey(m) ? statement.get(m) : request.get(m);
      if (v != null) {
        merged.put(m, v instanceof Date d ? d.getTime() / 1000L : v);
      }
    }
    merged.putIfAbsent("id_token_signed_response_alg", "PS256");
    merged.putIfAbsent("request_object_signing_alg", "PS256");
    merged.putIfAbsent("require_signed_request_object", Boolean.TRUE);
    merged.putIfAbsent("request_object_encryption_alg", "RSA-OAEP");
    merged.putIfAbsent("request_object_encryption_enc", "A256GCM");
    merged.putIfAbsent("authlete:frontChannelRequestObjectEncryptionRequired", Boolean.TRUE);
    merged.putIfAbsent("authlete:requestObjectEncryptionAlgMatchRequired", Boolean.TRUE);
    merged.putIfAbsent("authlete:requestObjectEncryptionEncMatchRequired", Boolean.TRUE);
    merged.putIfAbsent("token_endpoint_auth_signing_alg", "PS256");
    merged.putIfAbsent("backchannel_authentication_request_signing_alg", "PS256");
    merged.putIfAbsent("authorization_signed_response_alg", "PS256");
    merged.putIfAbsent("tls_client_certificate_bound_access_tokens", Boolean.TRUE);
    merged.putIfAbsent("id_token_encrypted_response_alg", "RSA-OAEP");
    merged.putIfAbsent("id_token_encrypted_response_enc", "A256GCM");
    merged.putIfAbsent("default_acr_values", List.of("urn:brasil:openbanking:loa3"));
    defaultFrom(merged, statement, "software_client_name", "client_name");
    defaultFrom(merged, statement, "software_tos_uri", "tos_uri");
    defaultFrom(merged, statement, "software_client_description", "client_description");
    defaultFrom(merged, statement, "software_policy_uri", "policy_uri");
    defaultFrom(merged, statement, "software_client_uri", "client_uri");
    defaultFrom(merged, statement, "software_logo_uri", "logo_uri");
    if (merged.get("scope") == null) {
      Set<String> scopes = new TreeSet<>();
      strings(merged, "software_roles", "the software statement")
          .forEach(r -> scopes.addAll(allowedScopes(r)));
      merged.put("scope", String.join(" ", scopes));
    }
    return merged;
  }

  private static void defaultFrom(
      Map<String, Object> merged, Map<String, Object> statement, String source, String target) {
    if (!merged.containsKey(target) && statement.containsKey(source)) {
      merged.put(target, statement.get(source));
    }
  }

  private static Set<String> allowedScopes(String role) {
    Set<String> scopes = ROLE_SCOPES.get(role);
    if (scopes == null) {
      throw error("invalid_software_statement", "Unknown role in 'software_roles': " + role);
    }
    return scopes;
  }

  private static void requireValue(
      Map<String, Object> request, Map<String, Object> statement, List<String> names, String expected) {
    for (String name : names) {
      String v = string(request, statement, name);
      if (v != null && !v.equals(expected)) {
        throw error("invalid_client_metadata", "'" + name + "' must be '" + expected + "'.");
      }
    }
  }

  private static String string(Map<String, Object> request, Map<String, Object> statement, String name) {
    Object v = statement.containsKey(name) ? statement.get(name) : request.get(name);
    if (v != null && !(v instanceof String)) {
      throw error("invalid_client_metadata", "'" + name + "' must be a string.");
    }
    return (String) v;
  }

  private static List<String> strings(Map<String, Object> map, String name, String where) {
    if (!(map.get(name) instanceof List<?> list)) {
      throw error("invalid_client_metadata", "'" + name + "' is missing from " + where + ".");
    }
    for (Object o : list) {
      if (!(o instanceof String)) {
        throw error("invalid_client_metadata", "'" + name + "' must be an array of strings.");
      }
    }
    return list.stream().map(String.class::cast).toList();
  }

  private static WebException error(String code, String description) {
    return error(code, description, 400);
  }

  private static WebException error(String code, String description, int status) {
    return new WebException(Responses.json(status, Responses.error(code, description)));
  }
}

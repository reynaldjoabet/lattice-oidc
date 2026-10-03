package com.lattice.oidc.federation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * Relying-party side of login through an external OpenID Provider: authorization code flow with
 * PKCE, nonce and state; ID token validation; and a UserInfo call whose subject must match.
 */
public final class Federation {

  private static final int TIMEOUT_MILLIS = 10_000;

  private final FederationConfig.Entry config;
  private volatile OIDCProviderMetadata metadata;
  private volatile IDTokenValidator validator;

  Federation(FederationConfig.Entry config) {
    this.config = config;
  }

  public String id() {
    return config.id();
  }

  public String name() {
    return config.server().name();
  }

  private OIDCProviderMetadata metadata() throws IOException {
    OIDCProviderMetadata m = metadata;
    if (m == null) {
      Issuer issuer = new Issuer(config.server().issuer());
      try {
        HTTPRequest req = new OIDCProviderConfigurationRequest(issuer).toHTTPRequest();
        req.setConnectTimeout(TIMEOUT_MILLIS);
        req.setReadTimeout(TIMEOUT_MILLIS);
        m = OIDCProviderMetadata.parse(req.send().getContentAsJSONObject());
      } catch (ParseException e) {
        throw new IOException("Invalid discovery document from " + issuer + ": " + e.getMessage(), e);
      }
      if (!issuer.equals(m.getIssuer())) {
        throw new IOException("Discovery document issuer mismatch: " + m.getIssuer());
      }
      metadata = m;
    }
    return m;
  }

  private IDTokenValidator validator() throws IOException {
    IDTokenValidator v = validator;
    if (v == null) {
      String alg = config.client().idTokenSignedResponseAlg();
      v =
          new IDTokenValidator(
              metadata().getIssuer(),
              new ClientID(config.client().clientId()),
              alg == null ? JWSAlgorithm.RS256 : JWSAlgorithm.parse(alg),
              metadata().getJWKSetURI().toURL());
      validator = v;
    }
    return v;
  }

  /** Builds the authentication request to redirect the browser to. */
  public URI authenticationRequest(String state, String verifier, String nonce) throws IOException {
    return new AuthenticationRequest.Builder(
            new ResponseType("code"),
            new Scope(
                OIDCScopeValue.OPENID,
                OIDCScopeValue.PROFILE,
                OIDCScopeValue.EMAIL,
                OIDCScopeValue.ADDRESS,
                OIDCScopeValue.PHONE),
            new ClientID(config.client().clientId()),
            redirectUri())
        .endpointURI(metadata().getAuthorizationEndpointURI())
        .state(new State(state))
        .nonce(new Nonce(nonce))
        .codeChallenge(new CodeVerifier(verifier), CodeChallengeMethod.S256)
        .build()
        .toURI();
  }

  /** Completes the flow from the callback URL and returns the verified UserInfo. */
  public UserInfo complete(URI callback, String state, String verifier, String nonce)
      throws IOException {
    AuthenticationResponse response;
    try {
      response = AuthenticationResponseParser.parse(callback);
    } catch (ParseException e) {
      throw new IOException("Malformed authentication response: " + e.getMessage(), e);
    }
    if (!new State(state).equals(response.getState())) {
      throw new IOException("State mismatch in the authentication response.");
    }
    if (response instanceof AuthenticationErrorResponse error) {
      throw new IOException(
          "The OpenID Provider returned an error: " + error.getErrorObject().getCode());
    }
    AuthorizationCode code = response.toSuccessResponse().getAuthorizationCode();

    OIDCTokenResponse tokens = token(code, verifier);
    IDTokenClaimsSet idToken = validateIdToken(tokens.getOIDCTokens().getIDToken(), nonce);
    UserInfo userInfo = userInfo(tokens.getOIDCTokens().getAccessToken());
    if (!idToken.getSubject().equals(userInfo.getSubject())) {
      throw new IOException("UserInfo subject does not match the ID token subject.");
    }
    return userInfo;
  }

  private OIDCTokenResponse token(AuthorizationCode code, String verifier) throws IOException {
    AuthorizationCodeGrant grant =
        new AuthorizationCodeGrant(code, redirectUri(), new CodeVerifier(verifier));
    URI endpoint = metadata().getTokenEndpointURI();
    String secret = config.client().clientSecret();
    TokenRequest request =
        secret == null || secret.isEmpty()
            ? new TokenRequest(endpoint, new ClientID(config.client().clientId()), grant)
            : new TokenRequest(
                endpoint,
                new ClientSecretBasic(new ClientID(config.client().clientId()), new Secret(secret)),
                grant);
    try {
      TokenResponse response = OIDCTokenResponseParser.parse(send(request.toHTTPRequest()));
      if (!response.indicatesSuccess()) {
        throw new IOException(
            "Token request failed: " + response.toErrorResponse().getErrorObject().getCode());
      }
      return (OIDCTokenResponse) response.toSuccessResponse();
    } catch (ParseException e) {
      throw new IOException("Malformed token response: " + e.getMessage(), e);
    }
  }

  private IDTokenClaimsSet validateIdToken(JWT idToken, String nonce) throws IOException {
    try {
      return validator().validate(idToken, new Nonce(nonce));
    } catch (BadJOSEException | JOSEException e) {
      throw new IOException("Invalid ID token: " + e.getMessage(), e);
    }
  }

  private UserInfo userInfo(AccessToken accessToken) throws IOException {
    try {
      UserInfoResponse response =
          UserInfoResponse.parse(
              send(
                  new UserInfoRequest(metadata().getUserInfoEndpointURI(), accessToken)
                      .toHTTPRequest()));
      if (!response.indicatesSuccess()) {
        throw new IOException(
            "UserInfo request failed: " + response.toErrorResponse().getErrorObject().getCode());
      }
      return response.toSuccessResponse().getUserInfo();
    } catch (ParseException e) {
      throw new IOException("Malformed UserInfo response: " + e.getMessage(), e);
    }
  }

  private static HTTPResponse send(HTTPRequest request) throws IOException {
    request.setConnectTimeout(TIMEOUT_MILLIS);
    request.setReadTimeout(TIMEOUT_MILLIS);
    return request.send();
  }

  private URI redirectUri() throws IOException {
    try {
      return new URI(config.client().redirectUri());
    } catch (URISyntaxException e) {
      throw new IOException("Invalid redirectUri for federation " + config.id(), e);
    }
  }
}

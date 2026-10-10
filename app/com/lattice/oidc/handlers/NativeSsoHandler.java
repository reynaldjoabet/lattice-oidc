package com.lattice.oidc.handlers;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.NativeSsoRequest;
import com.authlete.common.dto.NativeSsoResponse;
import com.authlete.common.dto.TokenResponse;
import com.lattice.oidc.common.Digests;
import com.lattice.oidc.common.JsonHelpers;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.security.UserSessions;
import com.lattice.oidc.stores.EphemeralStore;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import jakarta.inject.Inject;
import jakarta.inject.Provider;
import jakarta.inject.Singleton;
import play.mvc.Result;

/**
 * Implementation of "OpenID Connect Native SSO for Mobile Apps 1.0" on the token endpoint.
 *
 * <p>When a token request complies with the specification, Authlete returns the NATIVE_SSO action.
 * This class then validates or issues the device secret and calls Authlete's /nativesso API, which
 * generates the token response containing the {@code device_secret} and an ID token with the
 * {@code ds_hash} and {@code sid} claims. Device secrets are bound to the login session in which
 * they were created and stop working when that session ends. Only a hash of each secret is stored.
 */
@Singleton
public final class NativeSsoHandler {

  record DeviceSecret(String value, String hash, String sessionId) {}

  /** What is stored about a device secret: its hash and session, never the secret itself. */
  record Registered(String hash, String sessionId) {}

  private static final String NAMESPACE = "device-secret";

  private final Provider<AuthleteApi> api;
  private final UserSessions sessions;
  private final EphemeralStore store;
  private final LatticeConfig config;

  @Inject
  public NativeSsoHandler(
      Provider<AuthleteApi> api, UserSessions sessions, EphemeralStore store, LatticeConfig config) {
    this.api = api;
    this.sessions = sessions;
    this.store = store;
    this.config = config;
  }

  public Result process(TokenResponse token, Map<String, String> headers) {
    // The session ID used during the authorization request, associated with the refresh token or
    // with the subject token, must still identify an active login session.
    String sessionId = token.getSessionId();
    if (!sessions.isActive(sessionId)) {
      throw TokenResponses.error(
          400, "invalid_grant", "The login session associated with this request has ended.", headers);
    }
    // Validate the presented device secret, or create and register a new one.
    DeviceSecret deviceSecret = deviceSecret(token.getDeviceSecret(), token.getDeviceSecretHash(), sessionId, headers);

    // Call Authlete's /nativesso API.
    NativeSsoResponse response =
        api.get()
            .nativeSso(
                new NativeSsoRequest()
                    .setAccessToken(
                        token.getJwtAccessToken() != null
                            ? token.getJwtAccessToken()
                            : token.getAccessToken())
                    .setRefreshToken(token.getRefreshToken())
                    .setDeviceSecret(deviceSecret.value())
                    .setDeviceSecretHash(deviceSecret.hash()),
                null);
    return switch (response.getAction()) {
      case OK -> Responses.ok(response.getResponseContent(), headers);
      default -> Responses.serverError(response.getResponseContent(), headers);
    };
  }

  /**
   * The device secret to use.
   *
   * <ul>
   *   <li>No device secret is presented (authorization code / refresh token flows): a new one is
   *       issued.
   *   <li>A known device secret is presented whose hash (if given in the subject token) and session
   *       match: it is reused.
   *   <li>An unknown secret without a hash (regular flows): it is replaced with a new one.
   *   <li>Otherwise (token exchange with a mismatching secret): the request fails with
   *       {@code invalid_grant}.
   * </ul>
   */
  private DeviceSecret deviceSecret(
      String presented, String presentedHash, String sessionId, Map<String, String> headers) {
    if (presented == null) {
      return register(sessionId);
    }
    Optional<Registered> known =
        store.get(NAMESPACE, Digests.sha256Base64Url(presented)).map(entry -> JsonHelpers.read(entry.json(), Registered.class));
    if (known.isPresent()
        && (presentedHash == null || Objects.equals(known.get().hash(), presentedHash))
        && Objects.equals(known.get().sessionId(), sessionId)) {
      return new DeviceSecret(presented, known.get().hash(), sessionId);
    }
    if (presentedHash == null) {
      // An unknown secret during a regular login simply gets replaced.
      return register(sessionId);
    }
    throw TokenResponses.error(400, "invalid_grant", "The device secret is invalid.", headers);
  }

  private DeviceSecret register(String sessionId) {
    String value = UserSessions.randomId();
    DeviceSecret deviceSecret = new DeviceSecret(value, Digests.sha256Base64Url(value), sessionId);
    store.put(
        NAMESPACE,
        deviceSecret.hash(),
        null,
        null,
        JsonHelpers.write(new Registered(deviceSecret.hash(), sessionId)),
        config.sessionMaxLifespan());
    return deviceSecret;
  }
}

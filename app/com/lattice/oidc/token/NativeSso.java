package com.lattice.oidc.token;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.NativeSsoRequest;
import com.authlete.common.dto.NativeSsoResponse;
import com.authlete.common.dto.TokenResponse;
import com.lattice.oidc.config.LatticeConfig;
import com.lattice.oidc.http.Responses;
import com.lattice.oidc.session.UserSessions;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;
import play.cache.SyncCacheApi;
import play.mvc.Result;

/**
 * Implementation of "OpenID Connect Native SSO for Mobile Apps 1.0" on the token endpoint.
 *
 * <p>When a token request complies with the specification, Authlete returns the NATIVE_SSO action.
 * This class then validates or issues the device secret and calls Authlete's /nativesso API, which
 * generates the token response containing the {@code device_secret} and an ID token with the
 * {@code ds_hash} and {@code sid} claims. Device secrets are bound to the login session in which
 * they were created and stop working when that session ends.
 */
@Singleton
public final class NativeSso {

  record DeviceSecret(String value, String hash, String sessionId) {}

  private final Provider<AuthleteApi> api;
  private final UserSessions sessions;
  private final SyncCacheApi cache;
  private final LatticeConfig config;

  @Inject
  public NativeSso(
      Provider<AuthleteApi> api, UserSessions sessions, SyncCacheApi cache, LatticeConfig config) {
    this.api = api;
    this.sessions = sessions;
    this.cache = cache;
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
    DeviceSecret ds = deviceSecret(token.getDeviceSecret(), token.getDeviceSecretHash(), sessionId, headers);

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
                    .setDeviceSecret(ds.value())
                    .setDeviceSecretHash(ds.hash()),
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
    Optional<DeviceSecret> known = cache.get(key(presented));
    if (known.isPresent()
        && (presentedHash == null || Objects.equals(known.get().hash(), presentedHash))
        && Objects.equals(known.get().sessionId(), sessionId)) {
      return known.get();
    }
    if (presentedHash == null) {
      // An unknown secret during a regular login simply gets replaced.
      return register(sessionId);
    }
    throw TokenResponses.error(400, "invalid_grant", "The device secret is invalid.", headers);
  }

  private DeviceSecret register(String sessionId) {
    String value = UserSessions.randomId();
    DeviceSecret ds = new DeviceSecret(value, hash(value), sessionId);
    cache.set(key(value), ds, (int) config.sessionMaxLifespan().toSeconds());
    return ds;
  }

  static String hash(String value) {
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  private static String key(String value) {
    return "device-secret:" + hash(value);
  }
}

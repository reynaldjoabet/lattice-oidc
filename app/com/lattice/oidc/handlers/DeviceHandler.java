package com.lattice.oidc.handlers;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.DeviceCompleteRequest;
import com.authlete.common.dto.DeviceCompleteResponse;
import com.authlete.common.dto.DeviceVerificationRequest;
import com.authlete.common.dto.DeviceVerificationResponse;
import com.authlete.common.dto.Scope;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.models.DeviceApproval;
import com.lattice.oidc.security.UserSessions.LoginState;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

/** Protocol logic of the user-facing part of OAuth 2.0 Device Authorization Grant (RFC 8628). */
@Singleton
public final class DeviceHandler {

  private final Provider<AuthleteApi> api;
  private final LatticeConfig config;

  @Inject
  public DeviceHandler(Provider<AuthleteApi> api, LatticeConfig config) {
    this.api = api;
    this.config = config;
  }

  /** Looks up the user code with Authlete's /api/device/verification API. */
  public DeviceVerificationResponse verify(String userCode) {
    return api.get().deviceVerification(new DeviceVerificationRequest().setUserCode(userCode));
  }

  /** What the device authorization page shows for a valid user code. */
  public DeviceApproval approval(String userCode, DeviceVerificationResponse info) {
    List<String> scopes =
        info.getScopes() == null
            ? List.of()
            : Arrays.stream(info.getScopes()).map(Scope::getName).toList();
    String clientName =
        info.getClientName() != null
            ? info.getClientName()
            : info.isClientIdAliasUsed() ? info.getClientIdAlias() : String.valueOf(info.getClientId());
    return new DeviceApproval(userCode, clientName, scopes, info.getClaimNames(), info.getAcrs());
  }

  /**
   * Completes the device flow by calling Authlete's /api/device/complete API. On authorization,
   * the subject, the authentication time, the acr value that was actually used and the user's
   * claims are passed; otherwise the result is access_denied.
   */
  public DeviceCompleteResponse.Action complete(
      DeviceApproval approval, Optional<LoginState> user, boolean authorized) {
    DeviceCompleteRequest request =
        new DeviceCompleteRequest()
            .setUserCode(approval.userCode())
            .setResult(
                authorized
                    ? DeviceCompleteRequest.Result.AUTHORIZED
                    : DeviceCompleteRequest.Result.ACCESS_DENIED);
    if (authorized && user.isPresent()) {
      LoginState loginState = user.get();
      request
          .setSubject(loginState.user().getSubject())
          .setAuthTime(loginState.authTime())
          .setAcr(acr(approval.acrs()));
      Map<String, Object> claims = new ClaimsCollector(loginState.user()).collect(approval.claimNames(), null);
      if (claims != null) {
        request.setClaims(claims);
      }
    }
    return api.get().deviceComplete(request).getAction();
  }

  private String acr(String[] requested) {
    return requested == null
        ? null
        : Arrays.stream(requested).filter(config.satisfiedAcrs()::contains).findFirst().orElse(null);
  }
}

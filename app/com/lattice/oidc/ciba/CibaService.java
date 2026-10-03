package com.lattice.oidc.ciba;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.BackchannelAuthenticationCompleteRequest;
import com.authlete.common.dto.BackchannelAuthenticationCompleteRequest.Result;
import com.authlete.common.dto.BackchannelAuthenticationCompleteResponse;
import com.authlete.common.dto.BackchannelAuthenticationIssueResponse;
import com.authlete.common.dto.BackchannelAuthenticationResponse;
import com.authlete.common.dto.Scope;
import com.lattice.oidc.client.AuthleteExecutionContext;
import com.lattice.oidc.claims.ClaimsCollector;
import com.lattice.oidc.config.LatticeConfig;
import com.lattice.oidc.user.User;
import com.lattice.oidc.user.UserStore;
import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.cache.SyncCacheApi;
import play.libs.ws.WSClient;
import play.libs.ws.WSResponse;

/**
 * Drives the end-user's decision on the authentication device and reports it to Authlete
 * (/backchannel/authentication/complete), delivering ping/push notifications to the client.
 */
@Singleton
public final class CibaService {

  private static final Logger LOG = LoggerFactory.getLogger(CibaService.class);

  /** What is needed to complete a pending CIBA request. */
  public record Pending(String ticket, String subject, String[] claimNames, String[] acrs) {}

  private final Provider<AuthleteApi> api;
  private final AuthenticationDevice device;
  private final UserStore users;
  private final SyncCacheApi cache;
  private final WSClient ws;
  private final AuthleteExecutionContext ec;
  private final LatticeConfig config;

  @Inject
  public CibaService(
      Provider<AuthleteApi> api,
      AuthenticationDevice device,
      UserStore users,
      SyncCacheApi cache,
      WSClient ws,
      AuthleteExecutionContext ec,
      LatticeConfig config) {
    this.api = api;
    this.device = device;
    this.users = users;
    this.cache = cache;
    this.ws = ws;
    this.ec = ec;
    this.config = config;
  }

  /**
   * Starts communicating with the authentication device for end-user authentication and
   * authorization. Runs in the background so that the backchannel authentication response is
   * returned to the client immediately.
   *
   * <ul>
   *   <li>sync: wait for the end-user's decision on the device.
   *   <li>async: the device calls back {@code /api/backchannel/authentication/callback}.
   *   <li>poll: poll the device for the result.
   * </ul>
   */
  public void start(User user, BackchannelAuthenticationResponse ba, BackchannelAuthenticationIssueResponse issue) {
    Pending pending = new Pending(ba.getTicket(), user.getSubject(), ba.getClaimNames(), ba.getAcrs());
    String message = message(ba);
    int timeout = authTimeout(issue.getExpiresIn());
    String authReqId = issue.getAuthReqId();
    CompletableFuture.runAsync(
        () -> {
          try {
            switch (config.ciba().mode()) {
              case SYNC -> complete(pending, device.sync(user.getSubject(), message, timeout, authReqId));
              case ASYNC -> {
                String requestId = device.async(user.getSubject(), message, timeout, authReqId);
                cache.set(key(requestId), pending, Math.max(issue.getExpiresIn(), 60));
              }
              case POLL -> poll(pending, device.poll(user.getSubject(), message, timeout, authReqId));
            }
          } catch (RuntimeException e) {
            LOG.warn("CIBA authentication device interaction failed: {}", e.getMessage());
            fail(pending, Result.TRANSACTION_FAILED, "Communication with the authentication device failed.");
          }
        },
        ec.current());
  }

  /** Handles the device's asynchronous callback. Returns false for unknown request ids. */
  public boolean callback(String requestId, AuthenticationDevice.Outcome outcome) {
    Optional<Pending> pending = cache.get(key(requestId));
    if (pending.isEmpty()) {
      return false;
    }
    cache.remove(key(requestId));
    complete(pending.get(), outcome);
    return true;
  }

  private void poll(Pending pending, String requestId) {
    Duration interval = config.ciba().pollInterval();
    for (int i = 1; i <= config.ciba().pollMaxCount(); i++) {
      AuthenticationDevice.Outcome outcome = device.result(requestId);
      if (outcome != null) {
        complete(pending, outcome);
        return;
      }
      try {
        TimeUnit.MILLISECONDS.sleep(interval.toMillis());
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        break;
      }
    }
    fail(pending, Result.TRANSACTION_FAILED, "The end-user did not respond in time.");
  }

  /**
   * Completes the process with the result of end-user authentication and authorization, by calling
   * Authlete's /api/backchannel/authentication/complete API.
   */
  private void complete(Pending pending, AuthenticationDevice.Outcome outcome) {
    switch (outcome) {
      case ALLOW -> authorize(pending);
      case DENY -> fail(pending, Result.ACCESS_DENIED, "The end-user denied the request.");
      case TIMEOUT -> fail(pending, Result.TRANSACTION_FAILED, "The authentication device timed out.");
      default -> fail(pending, Result.TRANSACTION_FAILED, "Unrecognized result from the authentication device.");
    }
  }

  private void authorize(Pending pending) {
    Optional<User> user = users.bySubject(pending.subject());
    if (user.isEmpty()) {
      fail(pending, Result.TRANSACTION_FAILED, "The user no longer exists.");
      return;
    }
    // OK. The end-user has successfully authorized the client. Complete the process with the
    // authentication time, the acr value that was actually used and the user's claims.
    BackchannelAuthenticationCompleteRequest request =
        new BackchannelAuthenticationCompleteRequest()
            .setTicket(pending.ticket())
            .setSubject(pending.subject())
            .setResult(Result.AUTHORIZED)
            .setAuthTime(System.currentTimeMillis() / 1000L)
            .setAcr(acr(pending.acrs()));
    Map<String, Object> claims = new ClaimsCollector(user.get()).collect(pending.claimNames(), null);
    if (claims != null) {
      request.setClaims(claims);
    }
    send(request);
  }

  /**
   * The end-user authorization has not been successfully done. Complete the process with failure
   * (access_denied or transaction_failed, with an error description).
   */
  private void fail(Pending pending, Result result, String description) {
    send(
        new BackchannelAuthenticationCompleteRequest()
            .setTicket(pending.ticket())
            .setSubject(pending.subject())
            .setResult(result)
            .setErrorDescription(description));
  }

  private void send(BackchannelAuthenticationCompleteRequest request) {
    BackchannelAuthenticationCompleteResponse response =
        api.get().backchannelAuthenticationComplete(request);
    // 'action' in the response denotes the next action which
    // this service implementation should take.
    switch (response.getAction()) {
      // Send a notification to the client. This happens when the backchannel token delivery mode is
      // "ping" or "push".
      case NOTIFICATION -> notifyClient(response);
      // No action is required. This happens when the backchannel token delivery mode is "poll".
      case NO_ACTION -> {}
      // Server error.
      default -> LOG.error("CIBA completion failed: {}", response.getResultMessage());
    }
  }

  /** Ping/push mode: POST the result to the client notification endpoint (no redirects). */
  private void notifyClient(BackchannelAuthenticationCompleteResponse response) {
    if (response.getClientNotificationEndpoint() == null) {
      return;
    }
    Duration timeout = config.ciba().notificationTimeout();
    try {
      WSResponse r =
          ws.url(response.getClientNotificationEndpoint().toString())
              .setFollowRedirects(false)
              .setRequestTimeout(timeout)
              .addHeader("Authorization", "Bearer " + response.getClientNotificationToken())
              .setContentType("application/json")
              .post(response.getResponseContent())
              .toCompletableFuture()
              .get(timeout.toMillis() + 1_000L, TimeUnit.MILLISECONDS);
      if (r.getStatus() / 100 != 2 && r.getStatus() / 100 != 3) {
        LOG.warn("CIBA client notification returned HTTP {}", r.getStatus());
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    } catch (Exception e) {
      LOG.warn("CIBA client notification failed: {}", e.getMessage());
    }
  }

  private String acr(String[] requested) {
    if (requested == null) {
      return null;
    }
    return Arrays.stream(requested).filter(config.satisfiedAcrs()::contains).findFirst().orElse(null);
  }

  private int authTimeout(int expiresIn) {
    int t = (int) (config.ciba().authTimeoutRatio() * expiresIn);
    return Math.max(AuthenticationDevice.AUTH_TIMEOUT_MIN, Math.min(AuthenticationDevice.AUTH_TIMEOUT_MAX, t));
  }

  private static String message(BackchannelAuthenticationResponse ba) {
    StringBuilder sb =
        new StringBuilder("Client App (")
            .append(ba.getClientName())
            .append(") is requesting the following permissions.");
    Scope[] scopes = ba.getScopes();
    if (scopes != null && scopes.length > 0) {
      sb.append(" [Requested scopes]: ")
          .append(Arrays.stream(scopes).map(Scope::getName).collect(Collectors.joining(",")));
    }
    if (ba.getBindingMessage() != null) {
      sb.append(" [Binding message]: ").append(ba.getBindingMessage());
    }
    return sb.toString();
  }

  private static String key(String requestId) {
    return "ciba:" + requestId;
  }
}

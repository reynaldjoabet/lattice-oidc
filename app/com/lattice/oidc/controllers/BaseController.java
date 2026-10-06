package com.lattice.oidc.controllers;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.api.AuthleteApiException;
import com.lattice.oidc.client.AuthleteExecutionContext;
import com.lattice.oidc.common.Redaction;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.common.WebException;
import com.lattice.oidc.security.AuditService;
import com.lattice.oidc.security.LoginService;
import com.lattice.oidc.security.SecondFactors;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Supplier;
import jakarta.inject.Inject;
import jakarta.inject.Provider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.mvc.Controller;
import play.mvc.Http;
import play.mvc.Result;

/**
 * Base class for endpoints backed by Authlete. Work runs on the blocking Authlete pool; {@link
 * WebException}s become their response and unexpected failures a generic server_error, with
 * details only in the log.
 */
public abstract class BaseController extends Controller {

  private static final Logger LOG = LoggerFactory.getLogger(BaseController.class);

  @Inject private Provider<AuthleteApi> apiProvider;
  @Inject private AuthleteExecutionContext executionContext;
  @Inject protected AuditService audit;
  @Inject protected Requests requests;
  @Inject private SecondFactors secondFactors;

  protected AuthleteApi api() {
    return apiProvider.get();
  }

  protected CompletionStage<Result> async(Supplier<Result> work) {
    return CompletableFuture.supplyAsync(() -> run(work), executionContext.current());
  }

  /** Audits the outcome of a password login attempt. */
  /**
   * Audits the password step of a sign-in. With an authenticator app the sign-in isn't finished
   * yet: that is {@code SECOND_FACTOR_REQUIRED}, and {@code LOGIN_SUCCEEDED} follows the code.
   */
  protected void auditLogin(Http.RequestHeader request, String loginId, LoginService.Result result) {
    switch (result.outcome()) {
      case SUCCESS -> {
        String subject = result.user().get().getSubject();
        if (secondFactors.enrolled(subject)) {
          audit.record(request, AuditService.Event.SECOND_FACTOR_REQUIRED, "subject", subject, "method", "password", "factor", "totp");
        } else {
          audit.record(request, AuditService.Event.LOGIN_SUCCEEDED, "subject", subject, "method", "password");
        }
      }
      case LOCKED -> audit.record(request, AuditService.Event.LOGIN_LOCKED, "login_id", loginId, "method", "password");
      case UNAVAILABLE ->
          audit.record(request, AuditService.Event.LOGIN_FAILED, "login_id", loginId, "method", "password", "reason", "directory_unavailable");
      default -> audit.record(request, AuditService.Event.LOGIN_FAILED, "login_id", loginId, "method", "password");
    }
  }

  /** Audits a signed-in user re-entering their password before a sensitive change. */
  protected void auditPasswordConfirmation(Http.RequestHeader request, String subject, LoginService.Result result) {
    switch (result.outcome()) {
      case SUCCESS -> audit.record(request, AuditService.Event.PASSWORD_CONFIRMED, "subject", subject);
      case LOCKED -> audit.record(request, AuditService.Event.LOGIN_LOCKED, "subject", subject, "method", "password");
      default ->
          audit.record(request, AuditService.Event.LOGIN_FAILED, "subject", subject, "method", "password", "step", "confirmation");
    }
  }

  protected static Result run(Supplier<Result> work) {
    try {
      return work.get();
    } catch (WebException e) {
      return e.result();
    } catch (AuthleteApiException e) {
      LOG.error(
          "Authlete API call failed: status={}, message={}, body={}",
          e.getStatusCode(),
          e.getMessage(),
          Redaction.redact(e.getResponseBody()));
      return Responses.serverError(
          Responses.error("server_error", "The authorization server is temporarily unavailable."));
    } catch (RuntimeException e) {
      LOG.error("Unexpected error while processing request", e);
      return Responses.serverError(Responses.error("server_error", null));
    }
  }

  /** For Authlete actions this server does not know (newer Authlete versions). */
  protected static WebException unknownAction(String api, Object action) {
    LOG.error("Authlete {} returned an unknown action: {}", api, action);
    return new WebException(Responses.serverError(Responses.error("server_error", null)));
  }
}

package com.lattice.oidc.http;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.api.AuthleteApiException;
import com.lattice.oidc.client.AuthleteExecutionContext;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Supplier;
import javax.inject.Inject;
import javax.inject.Provider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.mvc.Controller;
import play.mvc.Result;

/**
 * Base class for endpoints backed by Authlete. Work runs on the blocking Authlete pool; {@link
 * WebException}s become their response and unexpected failures a generic server_error, with
 * details only in the log.
 */
public abstract class AuthleteController extends Controller {

  private static final Logger LOG = LoggerFactory.getLogger(AuthleteController.class);

  @Inject private Provider<AuthleteApi> apiProvider;
  @Inject private AuthleteExecutionContext authleteEc;
  @Inject protected Requests requests;

  protected AuthleteApi api() {
    return apiProvider.get();
  }

  protected CompletionStage<Result> async(Supplier<Result> work) {
    return CompletableFuture.supplyAsync(() -> run(work), authleteEc.current());
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
          e.getResponseBody());
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

package com.lattice.oidc.client.resilience;

import com.authlete.common.api.AuthleteApi;
import java.lang.reflect.Proxy;
import java.util.function.IntSupplier;

/**
 * Wraps the Authlete client in the resilience layer: response caching with stale fallback, retries
 * with exponential backoff and jitter, and a circuit breaker per Authlete method. See {@link
 * ResilientAuthleteApiInvocationHandler} for the behaviour.
 */
public final class ResilientAuthleteApi {

  /** The wrapped client, and how many breakers are open (for a metric). */
  public record Wrapped(AuthleteApi api, IntSupplier openBreakers) {}

  private ResilientAuthleteApi() {}

  public static Wrapped wrap(AuthleteApi delegate, ResilienceConfig config, ResilienceListener listener) {
    if (!config.isEnabled()) {
      return new Wrapped(delegate, () -> 0);
    }
    ResilientAuthleteApiInvocationHandler handler =
        new ResilientAuthleteApiInvocationHandler(delegate, config, listener);
    AuthleteApi api =
        (AuthleteApi)
            Proxy.newProxyInstance(AuthleteApi.class.getClassLoader(), new Class<?>[] {AuthleteApi.class}, handler);
    return new Wrapped(api, handler::openBreakers);
  }
}

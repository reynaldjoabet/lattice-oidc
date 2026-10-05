package com.lattice.oidc.metrics;

import com.authlete.common.api.AuthleteApi;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.time.Duration;

/** Wraps the Authlete client so every API call is timed, by method name and outcome. */
public final class MeteredAuthleteApi {

  private MeteredAuthleteApi() {}

  public static AuthleteApi wrap(AuthleteApi api, Metrics metrics) {
    return (AuthleteApi)
        Proxy.newProxyInstance(
            AuthleteApi.class.getClassLoader(),
            new Class<?>[] {AuthleteApi.class},
            (proxy, method, args) -> {
              if (method.getDeclaringClass() == Object.class) {
                return method.invoke(api, args);
              }
              long start = System.nanoTime();
              boolean success = false;
              try {
                Object result = method.invoke(api, args);
                success = true;
                return result;
              } catch (InvocationTargetException e) {
                throw e.getCause();
              } finally {
                metrics.authleteCall(method.getName(), success, Duration.ofNanos(System.nanoTime() - start));
              }
            });
  }
}

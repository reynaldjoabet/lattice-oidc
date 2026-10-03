package com.lattice.oidc.client;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.api.AuthleteApiException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/** Scriptable in-memory AuthleteApi for tests: answers per method name, records every call. */
public final class FakeAuthleteApi {

  private final Map<String, Function<Object[], Object>> answers = new ConcurrentHashMap<>();
  public final List<String> calls = new ArrayList<>();
  public final Map<String, Object[]> lastArgs = new ConcurrentHashMap<>();

  public FakeAuthleteApi answer(String method, Function<Object[], Object> answer) {
    answers.put(method, answer);
    return this;
  }

  /** The first argument of the latest call to {@code method}. */
  @SuppressWarnings("unchecked")
  public <T> T lastRequest(String method) {
    Object[] args = lastArgs.get(method);
    return args == null || args.length == 0 ? null : (T) args[0];
  }

  public long count(String method) {
    synchronized (calls) {
      return calls.stream().filter(method::equals).count();
    }
  }

  public static AuthleteApiException failure(int status) {
    return new AuthleteApiException("HTTP " + status, status, "status " + status, null);
  }

  public AuthleteApi api() {
    return (AuthleteApi)
        Proxy.newProxyInstance(
            AuthleteApi.class.getClassLoader(),
            new Class<?>[] {AuthleteApi.class},
            (proxy, method, args) -> {
              if (method.getDeclaringClass() == Object.class) {
                return method.getName().equals("toString") ? "FakeAuthleteApi" : null;
              }
              synchronized (calls) {
                calls.add(method.getName());
              }
              lastArgs.put(method.getName(), args == null ? new Object[0] : args);
              Function<Object[], Object> answer = answers.get(method.getName());
              if (answer == null) {
                throw new UnsupportedOperationException("Not scripted: " + method.getName());
              }
              return answer.apply(args);
            });
  }
}

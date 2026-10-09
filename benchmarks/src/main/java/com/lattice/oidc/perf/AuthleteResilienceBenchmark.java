package com.lattice.oidc.perf;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.AuthorizationRequest;
import com.authlete.common.dto.AuthorizationResponse;
import com.lattice.oidc.client.resilience.ResilienceConfig;
import com.lattice.oidc.client.resilience.ResilienceListener;
import com.lattice.oidc.client.resilience.ResilientAuthleteApi;
import java.lang.reflect.Proxy;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

/**
 * What the resilience layer adds to an Authlete call, against an instant fake Authlete. The real
 * call is an HTTP request of a few milliseconds, so anything here in microseconds or below is noise
 * next to it; the point is that a cache hit costs far less than that request, and a call that goes
 * through costs almost nothing extra.
 */
@Fork(2)
@Warmup(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class AuthleteResilienceBenchmark {

  private AuthleteApi direct;
  private AuthleteApi resilient;
  private AuthorizationRequest request;

  @Setup
  public void apis() {
    AuthorizationResponse answer = new AuthorizationResponse();
    direct =
        (AuthleteApi)
            Proxy.newProxyInstance(
                AuthleteApi.class.getClassLoader(),
                new Class<?>[] {AuthleteApi.class},
                (proxy, method, args) -> {
                  if (method.getDeclaringClass() == Object.class) {
                    return method.getName().equals("hashCode") ? 0 : method.getName().equals("equals") ? proxy == args[0] : "fake";
                  }
                  return method.getName().equals("getServiceConfiguration") ? "{\"issuer\":\"https://lattice.example\"}" : answer;
                });
    resilient = ResilientAuthleteApi.wrap(direct, new ResilienceConfig(), ResilienceListener.NONE).api();
    request = new AuthorizationRequest();
    resilient.getServiceConfiguration(true); // fill the cache
  }

  @Benchmark
  public String discoveryDirect() {
    return direct.getServiceConfiguration(true);
  }

  /** Answered from the cache: no call to Authlete. */
  @Benchmark
  public String discoveryCached() {
    return resilient.getServiceConfiguration(true);
  }

  @Benchmark
  public AuthorizationResponse authorizationDirect() {
    return direct.authorization(request);
  }

  /** Not cacheable: the breaker check, the call, and the success bookkeeping. */
  @Benchmark
  public AuthorizationResponse authorizationThroughTheLayer() {
    return resilient.authorization(request);
  }
}

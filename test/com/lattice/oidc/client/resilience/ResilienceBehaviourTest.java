package com.lattice.oidc.client.resilience;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.api.AuthleteApiException;
import com.authlete.common.dto.AuthorizationIssueRequest;
import com.authlete.common.dto.AuthorizationIssueResponse;
import com.authlete.common.dto.Client;
import com.lattice.oidc.client.FakeAuthleteApi;
import com.typesafe.config.ConfigFactory;
import java.net.ConnectException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Test;

/** Retries of writes, client eviction and introspection caching in the resilience layer. */
public class ResilienceBehaviourTest {

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private final List<String> events = new CopyOnWriteArrayList<>();

  private AuthleteApi api() {
    ResilienceConfig config =
        new ResilienceConfig(ConfigFactory.parseMap(Map.of("retry.base-delay", "1 ms", "retry.jitter", "0 ms")));
    return ResilientAuthleteApi.wrap(fake.api(), config, (method, event) -> events.add(method + ":" + event)).api();
  }

  /** Throws {@code error} for the first call, then answers. */
  private static java.util.function.Function<Object[], Object> failingOnce(RuntimeException error, Object answer) {
    AtomicInteger calls = new AtomicInteger();
    return args -> {
      if (calls.incrementAndGet() == 1) {
        throw error;
      }
      return answer;
    };
  }

  private static AuthleteApiException noResponse(Throwable cause) {
    return new AuthleteApiException("Authlete API call failed: " + cause.getMessage(), cause);
  }

  @Test
  public void aWriteIsNotRetriedAfterA5xx() {
    fake.answer("authorizationIssue", failingOnce(FakeAuthleteApi.failure(503), new AuthorizationIssueResponse()));
    assertThrows(AuthleteApiException.class, () -> api().authorizationIssue(new AuthorizationIssueRequest()));
    assertEquals("Authlete may have issued the code already", 1, fake.count("authorizationIssue"));
  }

  @Test
  public void aWriteIsNotRetriedAfterAReadTimeout() {
    fake.answer(
        "authorizationIssue", failingOnce(noResponse(new TimeoutException("read timed out")), new AuthorizationIssueResponse()));
    assertThrows(AuthleteApiException.class, () -> api().authorizationIssue(new AuthorizationIssueRequest()));
    assertEquals(1, fake.count("authorizationIssue"));
  }

  @Test
  public void aWriteIsRetriedWhenAuthleteCertainlyDidntProcessIt() {
    fake.answer(
        "authorizationIssue", failingOnce(noResponse(new ConnectException("Connection refused")), new AuthorizationIssueResponse()));
    api().authorizationIssue(new AuthorizationIssueRequest());
    assertEquals("never reached Authlete: safe to retry", 2, fake.count("authorizationIssue"));

    fake.answer("token", failingOnce(FakeAuthleteApi.failure(429), new com.authlete.common.dto.TokenResponse()));
    api().token(new com.authlete.common.dto.TokenRequest());
    assertEquals("a 429 was rejected unprocessed: safe to retry", 2, fake.count("token"));
  }

  @Test
  public void aReadIsRetriedAfterA5xx() {
    fake.answer("getServiceJwks", failingOnce(FakeAuthleteApi.failure(503), "{\"keys\":[]}"));
    assertEquals("{\"keys\":[]}", api().getServiceJwks(true, false));
    assertEquals(2, fake.count("getServiceJwks"));
    assertTrue(events.contains("getServiceJwks:retry"));
  }

  @Test
  public void changingAClientEvictsTheCachedCopy() {
    Client before = new Client();
    before.setClientName("Before");
    Client after = new Client();
    after.setClientName("After");
    AtomicInteger reads = new AtomicInteger();
    fake.answer("getClient", args -> reads.incrementAndGet() == 1 ? before : after)
        .answer("updateClient", args -> args[0]);
    AuthleteApi api = api();

    assertEquals("Before", api.getClient(42L).getClientName());
    assertEquals("cached", "Before", api.getClient(42L).getClientName());
    assertTrue(events.contains("getClient:cache_hit"));

    api.updateClient(after);
    assertEquals("the console shows the change at once", "After", api.getClient(42L).getClientName());
    assertEquals(2, fake.count("getClient"));
  }

  @Test
  public void introspectionIsNotCachedByDefault() {
    fake.answer("introspection", args -> new com.authlete.common.dto.IntrospectionResponse());
    AuthleteApi api = api();
    api.introspection(new com.authlete.common.dto.IntrospectionRequest().setToken("t"));
    api.introspection(new com.authlete.common.dto.IntrospectionRequest().setToken("t"));
    assertEquals("a revoked token must not introspect as active from a cache", 2, fake.count("introspection"));
  }
}

package com.lattice.oidc.perf;

import static play.inject.Bindings.bind;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.AuthorizationFailResponse;
import com.authlete.common.dto.AuthorizationIssueResponse;
import com.authlete.common.dto.AuthorizationResponse;
import com.authlete.common.dto.AuthorizedClientListResponse;
import com.authlete.common.dto.Client;
import com.authlete.common.dto.IntrospectionResponse;
import com.authlete.common.dto.Scope;
import com.authlete.common.dto.Service;
import com.authlete.common.types.ClientType;
import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.client.resilience.ResilienceConfig;
import com.lattice.oidc.client.resilience.ResilienceListener;
import com.lattice.oidc.client.resilience.ResilientAuthleteApi;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import play.Application;
import play.Mode;
import play.inject.guice.GuiceApplicationBuilder;
import play.test.Helpers;
import play.test.TestServer;

/**
 * Lattice in production mode on http://localhost:9000 with a scripted Authlete, for the HTTP load
 * tests (perf/run.sh). The scripted Authlete answers at once unless {@code PERF_AUTHLETE_LATENCY_MS}
 * adds a delay, which is how to see what a slow Authlete does to the server's threads. The
 * resilience layer is around it ({@code PERF_RESILIENCE=off} removes it). Storage,
 * Redis and the cache are configured by the usual environment variables ({@code LATTICE_STORAGE},
 * {@code DATABASE_URL}, {@code LATTICE_SHORT_LIVED_STATE}, {@code LATTICE_CACHE}, ...).
 *
 * <p>Runs until interrupted, or for {@code PERF_SERVER_SECONDS} (default 1800).
 */
public final class PerfServer {

  private PerfServer() {}

  private static Client client() {
    Client client = new Client();
    client.setClientId(42L);
    client.setClientName("Acme Notes");
    client.setClientType(ClientType.CONFIDENTIAL);
    return client;
  }

  /** Waits like a real Authlete call would, then answers. */
  private static Function<Object[], Object> after(long latencyMillis, Function<Object[], Object> answer) {
    return args -> {
      if (latencyMillis > 0) {
        try {
          Thread.sleep(latencyMillis);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }
      return answer.apply(args);
    };
  }

  public static void main(String[] args) throws Exception {
    long latency = Long.parseLong(System.getenv().getOrDefault("PERF_AUTHLETE_LATENCY_MS", "0"));
    long seconds = Long.parseLong(System.getenv().getOrDefault("PERF_SERVER_SECONDS", "1800"));
    int port = Integer.parseInt(System.getenv().getOrDefault("PERF_PORT", "9000"));

    FakeAuthleteApi fake = new FakeAuthleteApi();
    fake.answer("getServiceConfiguration", after(latency, a -> "{\"issuer\":\"http://localhost:" + port + "\",\"scopes_supported\":[\"openid\",\"profile\",\"email\"]}"))
        .answer("getServiceJwks", after(latency, a -> "{\"keys\":[]}"))
        .answer("getClientAuthorizationList", after(latency, a -> new AuthorizedClientListResponse()))
        .answer(
            "authorization",
            after(
                latency,
                a -> {
                  AuthorizationResponse r = new AuthorizationResponse();
                  r.setAction(AuthorizationResponse.Action.INTERACTION);
                  r.setTicket("perf-" + UUID.randomUUID());
                  r.setClient(client());
                  Service service = new Service();
                  service.setServiceName("Lattice");
                  r.setService(service);
                  r.setScopes(new Scope[] {new Scope().setName("openid"), new Scope().setName("profile")});
                  r.setClaims(new String[] {"name", "email"});
                  return r;
                }))
        .answer(
            "authorizationIssue",
            after(
                latency,
                a -> {
                  AuthorizationIssueResponse r = new AuthorizationIssueResponse();
                  r.setAction(AuthorizationIssueResponse.Action.LOCATION);
                  r.setResponseContent("http://localhost:" + port + "/account");
                  return r;
                }))
        .answer("authorizationFail", after(latency, a -> new AuthorizationFailResponse()))
        .answer(
            "introspection",
            after(
                latency,
                a -> {
                  IntrospectionResponse r = new IntrospectionResponse();
                  r.setAction(IntrospectionResponse.Action.OK);
                  r.setSubject("1001");
                  r.setScopes(new String[] {"openid"});
                  return r;
                }));

    Map<String, Object> settings = new HashMap<>();
    settings.put("lattice.admin.login-ids", List.of("john"));
    settings.put("lattice.metrics.enabled", true);
    settings.put("lattice.passkeys.offer-interval", "0s");
    // Production mode validates these at startup, although the scripted Authlete replaces the client.
    settings.put("authlete.service-id", "1");
    settings.put("authlete.service-access-token", "perf");
    settings.put("play.http.secret.key", "perf-server-secret-perf-server-secret-perf-server-secret");
    settings.put("play.filters.hosts.allowed", List.of("localhost:" + port, "127.0.0.1:" + port));
    // The scripted Authlete replaces the real client, so the resilience layer (cache, retries,
    // circuit breaker) is put around it as in the application, unless PERF_RESILIENCE=off.
    boolean resilience = !"off".equalsIgnoreCase(System.getenv().getOrDefault("PERF_RESILIENCE", "on"));
    AuthleteApi authlete =
        resilience ? ResilientAuthleteApi.wrap(fake.api(), new ResilienceConfig(), ResilienceListener.NONE).api() : fake.api();
    // Production mode: no code reloading and no development error pages, which would distort the numbers.
    Application app =
        new GuiceApplicationBuilder()
            .in(Mode.PROD)
            .configure(settings)
            .overrides(bind(AuthleteApi.class).toInstance(authlete))
            .build();
    TestServer server = Helpers.testServer(port, app);
    server.start();
    System.out.println("PERF SERVER READY http://localhost:" + port + " (Authlete latency " + latency + " ms, resilience " + (resilience ? "on" : "off") + ")");
    try {
      Thread.sleep(seconds * 1000);
    } catch (InterruptedException interrupted) {
      // stopped by the runner
    } finally {
      server.stop();
    }
  }
}

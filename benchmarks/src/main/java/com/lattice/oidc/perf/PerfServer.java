package com.lattice.oidc.perf;

import static play.inject.Bindings.bind;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.AuthorizationFailResponse;
import com.authlete.common.dto.AuthorizationIssueResponse;
import com.authlete.common.dto.AuthorizationResponse;
import com.authlete.common.dto.AuthorizationIssueRequest;
import com.authlete.common.dto.AuthorizedClientListResponse;
import com.authlete.common.dto.ClientAuthorizationGetListRequest;
import com.authlete.common.dto.TokenRevokeResponse;
import com.authlete.common.dto.Client;
import com.authlete.common.dto.ClientListResponse;
import com.authlete.common.dto.ClientSecretRefreshResponse;
import com.authlete.common.dto.IntrospectionResponse;
import com.authlete.common.dto.Scope;
import com.authlete.common.dto.PushedAuthReqResponse;
import com.authlete.common.dto.RevocationResponse;
import com.authlete.common.dto.Service;
import com.authlete.common.dto.StandardIntrospectionResponse;
import com.authlete.common.dto.TokenResponse;
import com.authlete.common.dto.UserInfoIssueResponse;
import com.authlete.common.dto.UserInfoResponse;
import com.authlete.common.types.ClientAuthMethod;
import com.authlete.common.types.ClientType;
import com.authlete.common.types.GrantType;
import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.client.resilience.ResilienceConfig;
import com.lattice.oidc.client.resilience.ResilienceListener;
import com.lattice.oidc.client.resilience.ResilientAuthleteApi;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
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
 * <p>To run several behind a load balancer, give each its own {@code PERF_PORT} and set {@code
 * PERF_PUBLIC_PORT} to the balancer's port; they then need a shared PostgreSQL and Redis
 * (perf/run.sh does all of this).
 *
 * <p>Runs until interrupted, or for {@code PERF_SERVER_SECONDS} (default 1800).
 */
public final class PerfServer {

  private PerfServer() {}

  private static Client client() {
    Client client = new Client();
    client.setClientId(42L);
    client.setClientName("Acme Notes");
    client.setClientUri(java.net.URI.create("https://notes.example"));
    client.setClientType(ClientType.CONFIDENTIAL);
    client.setTokenAuthMethod(ClientAuthMethod.CLIENT_SECRET_BASIC);
    client.setGrantTypes(new GrantType[] {GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN});
    client.setRedirectUris(new String[] {"https://notes.example/cb"});
    return client;
  }

  /** A second client, registered dynamically, so the operator console has something to filter. */
  private static Client television() {
    Client client = new Client();
    client.setClientId(43L);
    client.setClientName("Living Room TV");
    client.setClientType(ClientType.PUBLIC);
    client.setGrantTypes(new GrantType[] {GrantType.DEVICE_CODE});
    client.setDynamicallyRegistered(true);
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
    // The port clients (or the load balancer in front) use; requests carry it in their Host header.
    int publicPort = Integer.parseInt(System.getenv().getOrDefault("PERF_PUBLIC_PORT", String.valueOf(port)));

    FakeAuthleteApi fake = new FakeAuthleteApi();
    // Subject -> the clients the user has approved.
    Map<String, Set<Long>> authorized = new ConcurrentHashMap<>();
    fake.answer("getServiceConfiguration", after(latency, a -> "{\"issuer\":\"http://localhost:" + publicPort + "\",\"scopes_supported\":[\"openid\",\"profile\",\"email\"]}"))
        .answer("getServiceJwks", after(latency, a -> "{\"keys\":[]}"))
        // Approving an app (the issue call) remembers it for that user, as Authlete does: the account
        // page then lists it under connected apps, and "Remove access" forgets it.
        .answer(
            "getClientAuthorizationList",
            after(
                latency,
                a -> {
                  String subject = ((ClientAuthorizationGetListRequest) a[0]).getSubject();
                  AuthorizedClientListResponse r = new AuthorizedClientListResponse();
                  r.setSubject(subject);
                  List<Client> apps = new java.util.ArrayList<>();
                  for (long id : authorized.getOrDefault(subject, Set.of())) {
                    apps.add(id == 42L ? client() : television());
                  }
                  r.setClients(apps.toArray(Client[]::new));
                  r.setTotalCount(apps.size());
                  return r;
                }))
        .answer(
            "deleteClientAuthorization",
            after(
                latency,
                a -> {
                  authorized.getOrDefault((String) a[1], Set.of()).remove((Long) a[0]);
                  return null;
                }))
        // Signing out everywhere revokes the user's tokens: nothing is tracked here, so it reports one.
        .answer("tokenRevoke", after(latency, a -> new TokenRevokeResponse().setCount(1)))
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
                  authorized.computeIfAbsent(((AuthorizationIssueRequest) a[0]).getSubject(), k -> ConcurrentHashMap.newKeySet()).add(42L);
                  AuthorizationIssueResponse r = new AuthorizationIssueResponse();
                  r.setAction(AuthorizationIssueResponse.Action.LOCATION);
                  r.setResponseContent("http://localhost:" + publicPort + "/account");
                  return r;
                }))
        .answer("authorizationFail", after(latency, a -> new AuthorizationFailResponse()))
        // The endpoints API clients call: token, introspection by a resource server, UserInfo, PAR and
        // revocation. They answer at once, so what is measured is Lattice's own work around the call.
        .answer(
            "token",
            after(
                latency,
                a -> {
                  TokenResponse r = new TokenResponse();
                  r.setAction(TokenResponse.Action.OK);
                  r.setResponseContent("{\"access_token\":\"perf-token\",\"token_type\":\"Bearer\",\"expires_in\":3600}");
                  return r;
                }))
        .answer(
            "standardIntrospection",
            after(
                latency,
                a -> {
                  StandardIntrospectionResponse r = new StandardIntrospectionResponse();
                  r.setAction(StandardIntrospectionResponse.Action.OK);
                  r.setResponseContent("{\"active\":true,\"sub\":\"1001\",\"scope\":\"openid\",\"client_id\":\"42\"}");
                  return r;
                }))
        .answer(
            "userinfo",
            after(
                latency,
                a -> {
                  UserInfoResponse r = new UserInfoResponse();
                  r.setAction(UserInfoResponse.Action.OK);
                  r.setSubject("1001");
                  r.setClaims(new String[] {"name", "email"});
                  return r;
                }))
        .answer(
            "userinfoIssue",
            after(
                latency,
                a -> {
                  UserInfoIssueResponse r = new UserInfoIssueResponse();
                  r.setAction(UserInfoIssueResponse.Action.JSON);
                  r.setResponseContent("{\"sub\":\"1001\",\"name\":\"John Flibble Smith\"}");
                  return r;
                }))
        .answer(
            "pushAuthorizationRequest",
            after(
                latency,
                a -> {
                  PushedAuthReqResponse r = new PushedAuthReqResponse();
                  r.setAction(PushedAuthReqResponse.Action.CREATED);
                  r.setResponseContent("{\"request_uri\":\"urn:ietf:params:oauth:request_uri:perf\",\"expires_in\":90}");
                  return r;
                }))
        .answer(
            "revocation",
            after(
                latency,
                a -> {
                  RevocationResponse r = new RevocationResponse();
                  r.setAction(RevocationResponse.Action.OK);
                  r.setResponseContent("");
                  return r;
                }))
        // The operator console (/admin/clients): two clients, and the answers its buttons need.
        .answer(
            "getClientList",
            after(
                latency,
                a -> {
                  ClientListResponse r = new ClientListResponse();
                  r.setClients(new Client[] {client(), television()});
                  r.setTotalCount(2);
                  return r;
                }))
        .answer("getClient", after(latency, a -> ((Long) a[0]) == 42L ? client() : television()))
        .answer("updateClient", after(latency, a -> a[0]))
        .answer("deleteClient", after(latency, a -> null))
        .answer(
            "refreshClientSecret",
            after(
                latency,
                a -> {
                  ClientSecretRefreshResponse r = new ClientSecretRefreshResponse();
                  r.setNewClientSecret("demo-new-secret-0123456789");
                  return r;
                }))
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
    settings.put(
        "play.filters.hosts.allowed",
        List.of("localhost:" + port, "127.0.0.1:" + port, "localhost:" + publicPort, "127.0.0.1:" + publicPort));
    // Several servers can run on one machine (behind a load balancer): each needs its own cluster port.
    settings.put("pekko.remote.artery.canonical.port", 0);
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

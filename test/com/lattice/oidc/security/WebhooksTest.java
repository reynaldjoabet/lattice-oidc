package com.lattice.oidc.security;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.post;
import static com.lattice.oidc.OidcTestSupport.route;
import static com.lattice.oidc.OidcTestSupport.withCsrf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.common.JsonHelpers;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.Application;
import play.test.Helpers;

/** Audit events delivered to a webhook, signed as Standard Webhooks. */
public class WebhooksTest {

  private record Delivery(String id, String timestamp, String signature, String body) {}

  private final BlockingQueue<Delivery> received = new LinkedBlockingQueue<>();
  private HttpServer receiver;
  private Application app;

  @Before
  public void start() throws Exception {
    receiver = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    receiver.createContext(
        "/hook",
        exchange -> {
          String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
          received.add(
              new Delivery(
                  exchange.getRequestHeaders().getFirst("webhook-id"),
                  exchange.getRequestHeaders().getFirst("webhook-timestamp"),
                  exchange.getRequestHeaders().getFirst("webhook-signature"),
                  body));
          exchange.sendResponseHeaders(204, -1);
          exchange.close();
        });
    receiver.createContext(
        "/broken",
        exchange -> {
          exchange.getRequestBody().readAllBytes();
          exchange.sendResponseHeaders(500, -1);
          exchange.close();
        });
    receiver.start();
    String url = "http://127.0.0.1:" + receiver.getAddress().getPort() + "/hook";
    String broken = "http://127.0.0.1:" + receiver.getAddress().getPort() + "/broken";
    app =
        app(
            new FakeAuthleteApi(),
            Map.of(
                "lattice.webhooks.endpoints",
                List.of(
                    Map.of("url", url, "secret", "test-secret", "events", List.of("LOGIN_FAILED")),
                    Map.of("url", broken, "secret", "test-secret", "events", List.of("LOGIN_FAILED")))));
    Helpers.start(app);
  }

  @After
  public void stop() {
    Helpers.stop(app);
    receiver.stop(0);
  }

  @Test
  public void subscribedEventsArriveSignedAndOthersDoNot() throws Exception {
    route(app, withCsrf(post("/account/login", Map.of("loginId", "john", "password", "john", "next", "account"))));
    route(app, withCsrf(post("/account/login", Map.of("loginId", "john", "password", "wrong", "next", "account"))));

    Delivery delivery = received.poll(10, TimeUnit.SECONDS);
    assertTrue("a delivery arrived", delivery != null);
    Map<String, Object> body = JsonHelpers.readMap(delivery.body());
    assertEquals("LOGIN_FAILED", body.get("type"));
    @SuppressWarnings("unchecked")
    Map<String, Object> data = (Map<String, Object>) body.get("data");
    assertEquals("john", data.get("login_id"));

    String expected =
        Webhooks.signature(
            "test-secret".getBytes(StandardCharsets.UTF_8),
            delivery.id(),
            Long.parseLong(delivery.timestamp()),
            delivery.body());
    assertEquals("the signature verifies with the shared secret", "v1," + expected, delivery.signature());

    assertTrue("LOGIN_SUCCEEDED isn't subscribed", received.poll(1, TimeUnit.SECONDS) == null);
  }

  @Test
  public void theConsoleShowsDeliveriesAndErrorsPerEndpoint() throws Exception {
    route(app, withCsrf(post("/account/login", Map.of("loginId", "john", "password", "wrong", "next", "account"))));
    Webhooks webhooks = app.injector().instanceOf(Webhooks.class);
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    List<Webhooks.EndpointStatus> status = webhooks.status();
    while ((status.get(0).delivered() == 0 || status.get(1).retrying() == 0) && System.nanoTime() < deadline) {
      Thread.sleep(50);
      status = webhooks.status();
    }
    assertEquals(1, status.get(0).delivered());
    assertTrue(status.get(0).lastDeliveredAt().isPresent());
    assertEquals("LOGIN_FAILED", status.get(0).events());

    assertEquals(0, status.get(1).delivered());
    assertEquals("the first retry is waiting", 1, status.get(1).retrying());
    assertEquals("HTTP 500", status.get(1).lastError().orElse(null));

    String metrics = app.injector().instanceOf(com.lattice.oidc.metrics.Metrics.class).scrape();
    String host = "127.0.0.1:" + receiver.getAddress().getPort();
    assertTrue(metrics, metrics.contains("lattice_webhook_deliveries_total{endpoint=\"1\",host=\"" + host + "\",outcome=\"delivered\"} 1.0"));
    assertTrue(metrics.contains("lattice_webhook_deliveries_total{endpoint=\"2\",host=\"" + host + "\",outcome=\"retry\"} 1.0"));
    assertTrue(metrics.contains("lattice_webhook_retries_waiting{endpoint=\"2\",host=\"" + host + "\"} 1.0"));
    assertTrue("no paths, which can hold secrets", !metrics.contains("/broken"));
  }
}

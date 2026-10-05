package com.lattice.oidc.security;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.post;
import static com.lattice.oidc.OidcTestSupport.route;
import static com.lattice.oidc.OidcTestSupport.withCsrf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.common.Jsons;
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
    receiver.start();
    String url = "http://127.0.0.1:" + receiver.getAddress().getPort() + "/hook";
    app =
        app(
            new FakeAuthleteApi(),
            Map.of(
                "lattice.webhooks.endpoints",
                List.of(Map.of("url", url, "secret", "test-secret", "events", List.of("LOGIN_FAILED")))));
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
    Map<String, Object> body = Jsons.readMap(delivery.body());
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
}

package com.lattice.oidc.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.api.AuthleteApiException;
import com.authlete.common.dto.AuthorizationIssueRequest;
import com.lattice.oidc.metrics.Metrics;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.Test;
import play.Application;
import play.inject.guice.GuiceApplicationBuilder;
import play.test.Helpers;

/** The real Authlete client, behind the resilience layer, against a local port. */
public class AuthleteResilienceWiringTest {

  private static Application app(int port) {
    return new GuiceApplicationBuilder()
        .configure(
            Map.of(
                "authlete.base-url", "http://127.0.0.1:" + port,
                "authlete.service-id", "1",
                "authlete.service-access-token", "token",
                "authlete.read-timeout", "1 second",
                "authlete.resilience.retry.base-delay", "10 ms",
                "authlete.resilience.retry.jitter", "0 ms",
                "pekko.remote.artery.canonical.port", 0))
        .build();
  }

  /** Real HTTP calls to Authlete for an operation, read from the registry (a scrape would add health checks). */
  private static long calls(Application app, String operation) {
    return app.injector().instanceOf(Metrics.class).registry().find("lattice.authlete.calls").tag("operation", operation).timers().stream()
        .mapToLong(io.micrometer.core.instrument.Timer::count)
        .sum();
  }

  private static double counter(Application app, String name, String... tags) {
    var counter = app.injector().instanceOf(Metrics.class).registry().find(name).tags(tags).counter();
    return counter == null ? 0 : counter.count();
  }

  @Test
  public void refusedConnectionsAreRetriedEvenForWrites() throws Exception {
    int closed;
    try (ServerSocket probe = new ServerSocket(0)) {
      closed = probe.getLocalPort(); // nothing listens here once closed
    }
    Application app = app(closed);
    Helpers.running(
        app,
        () -> {
          AuthleteApi api = app.injector().instanceOf(AuthleteApi.class);
          assertThrows(AuthleteApiException.class, () -> api.getServiceConfiguration(false));
          assertThrows(AuthleteApiException.class, () -> api.authorizationIssue(new AuthorizationIssueRequest()));
          assertEquals("3 attempts", 3, calls(app, "getServiceConfiguration"));
          assertEquals("never reached Authlete, so even the write is retried", 3, calls(app, "authorizationIssue"));
          assertEquals(2.0, counter(app, "lattice.authlete.resilience", "operation", "authorizationIssue", "event", "retry"), 0);
          assertTrue(app.injector().instanceOf(Metrics.class).scrape().contains("lattice_authlete_circuit_open"));
        });
  }

  @Test
  public void aWriteIsNotRetriedAfterAReadTimeout() throws Exception {
    List<Socket> accepted = new CopyOnWriteArrayList<>();
    try (ServerSocket silent = new ServerSocket(0)) {
      // Accepts connections and never answers: the request was sent, so it may have been processed.
      Thread acceptor =
          Thread.ofVirtual()
              .start(
                  () -> {
                    try {
                      while (true) {
                        accepted.add(silent.accept());
                      }
                    } catch (Exception closed) {
                      // test over
                    }
                  });
      Application app = app(silent.getLocalPort());
      Helpers.running(
          app,
          () -> {
            AuthleteApi api = app.injector().instanceOf(AuthleteApi.class);
            assertThrows(AuthleteApiException.class, () -> api.authorizationIssue(new AuthorizationIssueRequest()));
            assertEquals("one attempt only", 1, calls(app, "authorizationIssue"));
          });
      acceptor.interrupt();
      for (Socket socket : accepted) {
        socket.close();
      }
    }
  }
}

package com.lattice.oidc.security;

import com.lattice.oidc.client.AuthleteExecutionContext;
import com.lattice.oidc.common.Jsons;
import com.typesafe.config.Config;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.apache.pekko.actor.ActorSystem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.libs.ws.WSClient;

/**
 * Sends audit events to webhook endpoints ({@code lattice.webhooks}), for a SIEM or alerting.
 * Delivery follows the Standard Webhooks convention: a JSON body {@code {type, timestamp, data}} and
 * the headers {@code webhook-id}, {@code webhook-timestamp} and {@code webhook-signature: v1,<HMAC-
 * SHA256>}, computed over {@code id.timestamp.body} with the endpoint's secret (a {@code whsec_}
 * secret is base64, any other is used as UTF-8 text).
 *
 * <p>Delivery is asynchronous and never delays the request. A failed delivery is retried after 5
 * seconds, 30 seconds and 2 minutes, then logged. Retries are kept on this server, so a restart
 * drops pending ones.
 */
@Singleton
public final class Webhooks {

  private static final Logger LOG = LoggerFactory.getLogger(Webhooks.class);
  static final List<Duration> RETRY_DELAYS = List.of(Duration.ofSeconds(5), Duration.ofSeconds(30), Duration.ofMinutes(2));

  /** One endpoint; {@code events} empty means every event. */
  public record Endpoint(String url, byte[] secret, Set<String> events) {
    boolean wants(String event) {
      return events.isEmpty() || events.contains(event);
    }
  }

  /**
   * For the operator console, on this server since startup: deliveries that succeeded, retries
   * waiting, deliveries given up after the last retry, and the last success and error.
   */
  public record EndpointStatus(
      String url,
      String events,
      long delivered,
      long retrying,
      long failed,
      Optional<Instant> lastDeliveredAt,
      Optional<Instant> lastErrorAt,
      Optional<String> lastError) {}

  /** Delivery figures of one endpoint. */
  private static final class Tracker {
    final AtomicLong delivered = new AtomicLong();
    final AtomicLong retrying = new AtomicLong();
    final AtomicLong failed = new AtomicLong();
    volatile Instant lastDeliveredAt;
    volatile Instant lastErrorAt;
    volatile String lastError;
  }

  private final List<Endpoint> endpoints;
  private final Map<Endpoint, Tracker> trackers = new IdentityHashMap<>();
  private final WSClient ws;
  private final ActorSystem actorSystem;
  private final AuthleteExecutionContext executionContext;

  @Inject
  public Webhooks(Config config, WSClient ws, ActorSystem actorSystem, AuthleteExecutionContext executionContext) {
    this.endpoints = endpoints(config.getConfig("lattice.webhooks"));
    this.ws = ws;
    this.actorSystem = actorSystem;
    this.executionContext = executionContext;
    endpoints.forEach(endpoint -> trackers.put(endpoint, new Tracker()));
    endpoints.forEach(endpoint -> LOG.info("Webhook endpoint: {} (events: {})", endpoint.url(), endpoint.events().isEmpty() ? "all" : endpoint.events()));
  }

  private static List<Endpoint> endpoints(Config webhooks) {
    List<Endpoint> endpoints = new ArrayList<>();
    for (Config endpoint : webhooks.getConfigList("endpoints")) {
      endpoints.add(endpoint(endpoint.getString("url"), endpoint.getString("secret"), endpoint.getStringList("events")));
    }
    // One endpoint from the environment (WEBHOOK_URL, WEBHOOK_SECRET, WEBHOOK_EVENTS).
    String url = webhooks.getString("url").trim();
    if (!url.isEmpty()) {
      List<String> events =
          Arrays.stream(webhooks.getString("events").split(",")).map(String::trim).filter(event -> !event.isEmpty()).toList();
      endpoints.add(endpoint(url, webhooks.getString("secret"), events));
    }
    return List.copyOf(endpoints);
  }

  private static Endpoint endpoint(String url, String secret, List<String> events) {
    if (secret.isBlank()) {
      throw new IllegalArgumentException("Webhook " + url + " needs a secret, so receivers can verify deliveries");
    }
    byte[] key =
        secret.startsWith("whsec_")
            ? Base64.getDecoder().decode(secret.substring("whsec_".length()))
            : secret.getBytes(StandardCharsets.UTF_8);
    return new Endpoint(url, key, Set.copyOf(events));
  }

  public boolean enabled() {
    return !endpoints.isEmpty();
  }

  /** Sends the audit record to every endpoint that wants its event. */
  public void deliver(Map<String, Object> record) {
    String event = String.valueOf(record.get("event"));
    String id = "msg_" + UUID.randomUUID();
    long timestamp = Instant.now().getEpochSecond();
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("type", event);
    body.put("timestamp", record.get("ts"));
    body.put("data", record);
    String json = Jsons.write(body);
    for (Endpoint endpoint : endpoints) {
      if (endpoint.wants(event)) {
        send(endpoint, id, timestamp, json, 0);
      }
    }
  }

  private void send(Endpoint endpoint, String id, long timestamp, String json, int attempt) {
    ws.url(endpoint.url())
        .setFollowRedirects(false)
        .setRequestTimeout(Duration.ofSeconds(10))
        .setContentType("application/json")
        .addHeader("webhook-id", id)
        .addHeader("webhook-timestamp", Long.toString(timestamp))
        .addHeader("webhook-signature", "v1," + signature(endpoint.secret(), id, timestamp, json))
        .post(json)
        .whenComplete(
            (response, error) -> {
              Tracker tracker = trackers.get(endpoint);
              if (attempt > 0) {
                tracker.retrying.decrementAndGet();
              }
              if (error == null && response.getStatus() / 100 == 2) {
                tracker.delivered.incrementAndGet();
                tracker.lastDeliveredAt = Instant.now();
                return;
              }
              String reason = error != null ? error.getMessage() : "HTTP " + response.getStatus();
              tracker.lastErrorAt = Instant.now();
              tracker.lastError = reason;
              if (attempt < RETRY_DELAYS.size()) {
                tracker.retrying.incrementAndGet();
                actorSystem
                    .scheduler()
                    .scheduleOnce(
                        RETRY_DELAYS.get(attempt), () -> send(endpoint, id, timestamp, json, attempt + 1), executionContext);
              } else {
                tracker.failed.incrementAndGet();
                LOG.warn("Webhook {} to {} failed after {} attempts: {}", id, endpoint.url(), attempt + 1, reason);
              }
            });
  }

  /** The Standard Webhooks signature: base64 HMAC-SHA256 of {@code id.timestamp.body}. */
  static String signature(byte[] secret, String id, long timestamp, String body) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(secret, "HmacSHA256"));
      byte[] digest = mac.doFinal((id + "." + timestamp + "." + body).getBytes(StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(digest);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Each endpoint's delivery figures, in configuration order. */
  public List<EndpointStatus> status() {
    return endpoints.stream()
        .map(
            endpoint -> {
              Tracker tracker = trackers.get(endpoint);
              return new EndpointStatus(
                  endpoint.url(),
                  endpoint.events().isEmpty() ? "All events" : String.join(", ", new TreeSet<>(endpoint.events())),
                  tracker.delivered.get(),
                  tracker.retrying.get(),
                  tracker.failed.get(),
                  Optional.ofNullable(tracker.lastDeliveredAt),
                  Optional.ofNullable(tracker.lastErrorAt),
                  Optional.ofNullable(tracker.lastError));
            })
        .toList();
  }

  /** For tests and the console: the configured endpoints' URLs. */
  public List<String> urls() {
    return endpoints.stream().map(Endpoint::url).collect(Collectors.toList());
  }
}

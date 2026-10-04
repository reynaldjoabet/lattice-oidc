package com.lattice.oidc.controllers;

import com.lattice.oidc.client.AuthleteHealth;
import com.lattice.oidc.client.ServerMetadata;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.handlers.IdentityProviders;
import com.lattice.oidc.models.AdminPage;
import com.lattice.oidc.models.User;
import com.lattice.oidc.security.LoginService;
import com.lattice.oidc.security.UserSessions;
import com.lattice.oidc.stores.CounterStore;
import com.lattice.oidc.stores.EphemeralStore;
import com.lattice.oidc.security.UserSessions.LoginState;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletionStage;
import javax.inject.Inject;
import play.mvc.Http;
import play.mvc.Result;

/**
 * Operator console ({@code GET /admin}): Authlete status, sessions, identity providers, cache
 * statistics and recent audit events. Only users whose login ID is in {@code
 * lattice.admin.login-ids} may open it, after signing in normally (password, lockout, CSRF);
 * everyone else gets 403, and anonymous visitors the sign-in page.
 */
public final class AdminController extends BaseController {

  private static final Set<String> GOOD_EVENTS =
      Set.of("LOGIN_SUCCEEDED", "CONSENT_GRANTED", "DEVICE_AUTHORIZED", "CIBA_APPROVED", "ACCOUNT_LINKED");
  private static final Set<String> BAD_EVENTS =
      Set.of("LOGIN_FAILED", "LOGIN_LOCKED", "BROKERED_LOGIN_FAILED");

  private final UserSessions sessions;
  private final LatticeConfig config;
  private final com.typesafe.config.Config rawConfig;
  private final AuthleteHealth authlete;
  private final ServerMetadata server;
  private final IdentityProviders providers;
  private final EphemeralStore ephemeral;
  private final CounterStore counters;

  @Inject
  public AdminController(
      UserSessions sessions,
      LatticeConfig config,
      com.typesafe.config.Config rawConfig,
      AuthleteHealth authlete,
      ServerMetadata server,
      IdentityProviders providers,
      EphemeralStore ephemeral,
      CounterStore counters) {
    this.sessions = sessions;
    this.config = config;
    this.rawConfig = rawConfig;
    this.authlete = authlete;
    this.server = server;
    this.providers = providers;
    this.ephemeral = ephemeral;
    this.counters = counters;
  }

  /** Whether the user may open the operator console. Accounts without a login ID never may. */
  static boolean isAdmin(User user, LatticeConfig config) {
    return user.loginId() != null
        && config.adminLoginIds().stream().anyMatch(id -> id.equalsIgnoreCase(user.loginId()));
  }

  public CompletionStage<Result> index(Http.Request request) {
    return async(
        () -> {
          Optional<LoginState> current = sessions.current(request);
          if (current.isEmpty()) {
            return AccountController.loginPage(request, "admin", Optional.empty(), 200);
          }
          if (!isAdmin(current.get().user(), config)) {
            return Pages.message(request, 403, "No access", "Your account can't open the operator console.");
          }
          Map<String, String> health = authlete.check();
          boolean up = "UP".equals(health.get("status"));
          Optional<String> issuer = Optional.empty();
          if (up) {
            try {
              issuer = Optional.of(server.issuer());
            } catch (RuntimeException e) {
              issuer = Optional.empty();
            }
          }
          long activeSessions = sessions.countActive();
          List<AdminPage.StorageRow> rows = new java.util.ArrayList<>();
          rows.add(new AdminPage.StorageRow("sessions", activeSessions));
          ephemeral.counts().forEach((name, entries) -> rows.add(new AdminPage.StorageRow(name, entries)));
          AdminPage page =
              new AdminPage(
                  current.get().user().displayName(),
                  issuer,
                  up,
                  Optional.ofNullable(health.get("reason")),
                  activeSessions,
                  providers.links().stream().map(link -> link.name()).toList(),
                  counters.countAtLeast(LoginService.ACCOUNT_PREFIX, 1),
                  storageDescription(),
                  rows,
                  audit.recent().stream().map(AdminController::event).toList());
          return Responses.of(200, views.html.oidc.admin.render(page, request).body(), Responses.HTML, null)
              .withHeader(CACHE_CONTROL, "no-store");
        });
  }

  /** Where state is kept, in words, from lattice.storage, short-lived-state and cache.type. */
  private String storageDescription() {
    String storage =
        config.storage() == LatticeConfig.Storage.POSTGRES
            ? "PostgreSQL, shared by every server"
            : "In memory on this server; lost on restart";
    String shortLived =
        rawConfig.getString("lattice.short-lived-state").equalsIgnoreCase("redis")
            ? "Single-use state and counters in Redis."
            : "";
    String cache =
        switch (rawConfig.getString("lattice.cache.type").toLowerCase(java.util.Locale.ROOT)) {
          case "local" -> "Read cache on each server.";
          case "redis" -> "Read cache in Redis.";
          default -> "";
        };
    return String.join(" ", storage + ".", shortLived, cache).trim();
  }

  private static AdminPage.Event event(Map<String, Object> record) {
    String name = String.valueOf(record.get("event"));
    Object client = record.containsKey("client_id") ? record.get("client_id") : record.get("client");
    String time = String.valueOf(record.get("ts"));
    // "2026-10-04T09:12:03.123Z" → "2026-10-04 09:12:03"
    String shown = time.length() >= 19 ? time.substring(0, 19).replace('T', ' ') : time;
    String tone = GOOD_EVENTS.contains(name) ? "good" : BAD_EVENTS.contains(name) ? "bad" : "neutral";
    return new AdminPage.Event(
        shown,
        name,
        text(record.containsKey("subject") ? record.get("subject") : record.get("login_id")),
        text(client),
        text(record.get("ip")),
        tone);
  }

  private static String text(Object value) {
    return value == null ? "—" : value.toString();
  }
}

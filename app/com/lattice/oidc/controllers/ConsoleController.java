package com.lattice.oidc.controllers;

import com.authlete.common.api.AuthleteApiException;
import com.authlete.common.dto.Client;
import com.authlete.common.dto.ClientExtension;
import com.authlete.common.dto.ClientListResponse;
import com.authlete.common.dto.ClientSecretRefreshResponse;
import com.authlete.common.types.ClientAuthMethod;
import com.lattice.oidc.client.ServerMetadata;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.models.ConsoleClient;
import com.lattice.oidc.security.AuditService;
import com.lattice.oidc.security.SecurityStats;
import com.lattice.oidc.security.UserSessions;
import com.lattice.oidc.security.UserSessions.LoginState;
import com.lattice.oidc.stores.PasskeyStore;
import com.lattice.oidc.stores.UserStore;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;
import javax.inject.Inject;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;

/**
 * Operator console pages beyond the overview (admins only, like {@link AdminController}).
 *
 * <ul>
 *   <li>{@code GET /admin/clients}: registered clients, searchable and filterable by how they
 *       were registered (screen 34).
 *   <li>{@code GET|POST /admin/clients/:id}: view and edit a client (screen 35).
 *   <li>{@code POST /admin/clients/:id/secret}: rotate the client secret; the new one is shown
 *       once (screen 36). Authlete replaces the secret immediately.
 *   <li>{@code POST /admin/clients/:id/delete}: delete the client.
 *   <li>{@code GET /admin/security}: failed sign-ins, locked accounts, passkey adoption and "not
 *       me" reports (screen 38).
 * </ul>
 */
public final class ConsoleController extends BaseController {

  /** Token endpoint authentication methods offered in the editor. */
  static final List<String> AUTH_METHODS =
      List.of("client_secret_basic", "client_secret_post", "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth", "none");

  private static final int PAGE_SIZE = 200;

  private final UserSessions sessions;
  private final LatticeConfig config;
  private final ServerMetadata server;
  private final SecurityStats stats;
  private final PasskeyStore passkeys;
  private final UserStore users;

  @Inject
  public ConsoleController(
      UserSessions sessions,
      LatticeConfig config,
      ServerMetadata server,
      SecurityStats stats,
      PasskeyStore passkeys,
      UserStore users) {
    this.sessions = sessions;
    this.config = config;
    this.server = server;
    this.stats = stats;
    this.passkeys = passkeys;
    this.users = users;
  }

  // ---------------------------------------------------------------- clients

  public CompletionStage<Result> clients(Http.Request request, String query, String registration) {
    return admin(
        request,
        state -> {
          ClientListResponse response = api().getClientList(0, PAGE_SIZE);
          List<ConsoleClient> clients = new ArrayList<>();
          if (response.getClients() != null) {
            for (Client client : response.getClients()) {
              ConsoleClient shown = ConsoleClient.of(client);
              boolean registeredAsAsked =
                  switch (registration) {
                    case "dynamic" -> shown.dynamic();
                    case "console" -> !shown.dynamic();
                    default -> true;
                  };
              if (registeredAsAsked && shown.matches(query)) {
                clients.add(shown);
              }
            }
          }
          return html(
              views.html.oidc.consoleClients
                  .render(clients, query, registration, response.getTotalCount() > PAGE_SIZE, request)
                  .body());
        });
  }

  public CompletionStage<Result> client(Http.Request request, Long id) {
    return admin(request, state -> found(id).map(client -> editor(request, client, List.of(), false, 200)).orElseGet(ConsoleController::backToClients));
  }

  public CompletionStage<Result> update(Http.Request request, Long id) {
    return admin(
        request,
        state -> {
          Optional<Client> found = found(id);
          if (found.isEmpty()) {
            return backToClients();
          }
          Client client = found.get();
          Map<String, String[]> form = Requests.form(request);
          List<String> problems = new ArrayList<>();
          String name = Optional.ofNullable(Requests.first(form, "name")).map(String::trim).orElse("");
          if (name.isEmpty()) {
            problems.add("Enter a name.");
          }
          URI website = uri(form, "website", problems, "Website");
          URI privacy = uri(form, "privacyPolicy", problems, "Privacy policy");
          URI logo = uri(form, "logo", problems, "Logo URL");
          List<String> redirectUris = new ArrayList<>();
          for (String line : Optional.ofNullable(Requests.first(form, "redirectUris")).orElse("").split("\\R")) {
            String value = line.trim();
            if (value.isEmpty()) {
              continue;
            }
            if (!validRedirect(value)) {
              problems.add("Redirect URI " + value + " must be an absolute HTTPS URL (http only for localhost) without a fragment.");
            }
            redirectUris.add(value);
          }
          String method = Optional.ofNullable(Requests.first(form, "tokenAuthMethod")).orElse("");
          if (!AUTH_METHODS.contains(method)) {
            problems.add("Choose a client authentication method.");
          }
          if (!problems.isEmpty()) {
            return editor(request, client, problems, false, 400);
          }
          List<String> supported = supportedScopes(client);
          Set<String> chosen = new LinkedHashSet<>(Arrays.asList(Optional.ofNullable(form.get("scope")).orElse(new String[0])));
          chosen.retainAll(supported);
          ClientExtension extension = client.getExtension() != null ? client.getExtension() : new ClientExtension();
          boolean limited = !chosen.isEmpty() && chosen.size() < supported.size();
          extension.setRequestableScopesEnabled(limited);
          extension.setRequestableScopes(limited ? chosen.toArray(String[]::new) : null);
          client
              .setClientName(name)
              .setClientUri(website)
              .setPolicyUri(privacy)
              .setLogoUri(logo)
              .setRedirectUris(redirectUris.toArray(String[]::new))
              .setPkceRequired(form.containsKey("pkceRequired"))
              .setParRequired(form.containsKey("parRequired"))
              .setDpopRequired(form.containsKey("dpopRequired"))
              .setTokenAuthMethod(ClientAuthMethod.valueOf(method.toUpperCase(Locale.ROOT)))
              .setExtension(extension);
          Client updated;
          try {
            updated = api().updateClient(client);
          } catch (AuthleteApiException e) {
            return editor(request, client, List.of("Authlete rejected the change: " + reason(e)), false, 400);
          }
          audit.record(request, AuditService.Event.CLIENT_UPDATED, "client_id", id, "subject", state.user().getSubject());
          return editor(request, updated, List.of(), true, 200);
        });
  }

  public CompletionStage<Result> rotateSecret(Http.Request request, Long id) {
    return admin(
        request,
        state -> {
          Optional<Client> found = found(id);
          if (found.isEmpty()) {
            return backToClients();
          }
          ClientSecretRefreshResponse response = api().refreshClientSecret(id);
          audit.record(request, AuditService.Event.CLIENT_SECRET_ROTATED, "client_id", id, "subject", state.user().getSubject());
          ConsoleClient client = ConsoleClient.of(found.get());
          return html(views.html.oidc.consoleSecret.render(client, response.getNewClientSecret(), request).body());
        });
  }

  public CompletionStage<Result> delete(Http.Request request, Long id) {
    return admin(
        request,
        state -> {
          if (found(id).isPresent()) {
            api().deleteClient(id);
            audit.record(request, AuditService.Event.CLIENT_DELETED, "client_id", id, "subject", state.user().getSubject());
          }
          return Results.seeOther(com.lattice.oidc.controllers.routes.ConsoleController.clients("", "all"));
        });
  }

  // ---------------------------------------------------------------- audit log

  /** {@code GET /admin/audit}: stored audit events, newest first, filterable, 50 per page. */
  public CompletionStage<Result> audit(Http.Request request, String event, String subject, Long before) {
    return admin(
        request,
        state -> {
          Optional<String> eventFilter = Optional.of(event.trim()).filter(value -> !value.isEmpty());
          Optional<String> subjectFilter = Optional.of(subject.trim()).filter(value -> !value.isEmpty());
          List<Map<String, Object>> records =
              audit.search(
                  new com.lattice.oidc.stores.AuditEventStore.Query(
                      eventFilter, subjectFilter, Optional.ofNullable(before).filter(id -> id > 0), AUDIT_PAGE + 1));
          boolean more = records.size() > AUDIT_PAGE;
          List<Map<String, Object>> page = more ? records.subList(0, AUDIT_PAGE) : records;
          Optional<Long> older =
              more ? Optional.of(((Number) page.get(page.size() - 1).get("id")).longValue()) : Optional.empty();
          List<String> events =
              java.util.Arrays.stream(AuditService.Event.values()).map(Enum::name).sorted().toList();
          return html(
              views.html.oidc.consoleAudit
                  .render(
                      page.stream().map(AdminController::event).toList(),
                      events,
                      eventFilter.orElse(""),
                      subjectFilter.orElse(""),
                      older,
                      request)
                  .body());
        });
  }

  private static final int AUDIT_PAGE = 50;

  // ---------------------------------------------------------------- security

  public CompletionStage<Result> security(Http.Request request) {
    return admin(
        request,
        state -> {
          long accounts = users.count();
          long withPasskeys = passkeys.accountsWithPasskeys();
          int adoption = accounts == 0 ? 0 : (int) Math.round(100.0 * withPasskeys / accounts);
          return html(
              views.html.oidc.consoleSecurity
                  .render(stats.summary(), stats.lockedAccounts(config.loginLockout()), adoption, request)
                  .body());
        });
  }

  // ---------------------------------------------------------------- helpers

  private Result editor(Http.Request request, Client client, List<String> problems, boolean saved, int status) {
    return Responses.of(
            status,
            views.html.oidc.consoleClient
                .render(ConsoleClient.of(client), supportedScopes(client), AUTH_METHODS, problems, saved, request)
                .body(),
            Responses.HTML,
            null)
        .withHeader(CACHE_CONTROL, "no-store");
  }

  /** The service's scopes, plus any the client is limited to that the service no longer lists. */
  @SuppressWarnings("unchecked")
  private List<String> supportedScopes(Client client) {
    Set<String> scopes = new LinkedHashSet<>();
    try {
      Object supported = server.get("scopes_supported");
      if (supported instanceof List<?> list) {
        list.forEach(scope -> scopes.add(String.valueOf(scope)));
      }
    } catch (RuntimeException e) {
      // Shown without the service's list.
    }
    ConsoleClient.of(client).requestableScopes().ifPresent(scopes::addAll);
    return List.copyOf(scopes);
  }

  private Optional<Client> found(long id) {
    try {
      return Optional.ofNullable(api().getClient(id));
    } catch (AuthleteApiException e) {
      if (e.getStatusCode() == 404 || e.getStatusCode() == 400) {
        return Optional.empty();
      }
      throw e;
    }
  }

  private static Result backToClients() {
    return Results.seeOther(com.lattice.oidc.controllers.routes.ConsoleController.clients("", "all"));
  }

  private static URI uri(Map<String, String[]> form, String field, List<String> problems, String label) {
    String value = Optional.ofNullable(Requests.first(form, field)).map(String::trim).orElse("");
    if (value.isEmpty()) {
      return null;
    }
    try {
      URI uri = URI.create(value);
      if ("https".equals(uri.getScheme()) && uri.getHost() != null) {
        return uri;
      }
    } catch (IllegalArgumentException e) {
      // Reported below.
    }
    problems.add(label + " must be an HTTPS URL.");
    return null;
  }

  static boolean validRedirect(String value) {
    try {
      URI uri = URI.create(value);
      if (uri.getFragment() != null || uri.getScheme() == null) {
        return false;
      }
      if ("https".equals(uri.getScheme())) {
        return uri.getHost() != null;
      }
      if ("http".equals(uri.getScheme())) {
        return "localhost".equals(uri.getHost()) || "127.0.0.1".equals(uri.getHost()) || "[::1]".equals(uri.getHost());
      }
      // Private-use URI schemes of native apps (RFC 8252), e.g. com.example.app:/callback.
      return uri.getScheme().contains(".");
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  private static String reason(AuthleteApiException e) {
    return e.getResponseBody() != null && e.getResponseBody().contains("resultMessage")
        ? e.getResponseBody().replaceAll(".*\"resultMessage\"\\s*:\\s*\"([^\"]*)\".*", "$1")
        : e.getMessage();
  }

  private CompletionStage<Result> admin(Http.Request request, Function<LoginState, Result> action) {
    return async(
        () -> {
          Optional<LoginState> current = sessions.current(request);
          if (current.isEmpty()) {
            return AccountController.loginPage(request, "admin", Optional.empty(), 200);
          }
          if (!AdminController.isAdmin(current.get().user(), config)) {
            return Pages.message(request, 403, "No access", "Your account can't open the operator console.");
          }
          return action.apply(current.get());
        });
  }

  private static Result html(String body) {
    return Responses.of(200, body, Responses.HTML, null).withHeader(CACHE_CONTROL, "no-store");
  }
}

package com.lattice.oidc.models;

import com.authlete.common.dto.Client;
import com.authlete.common.types.ClientType;
import com.authlete.common.types.GrantType;
import java.net.URI;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/** A registered client as the operator console shows it (screens 34 and 35). */
public record ConsoleClient(
    long id,
    String clientId,
    String name,
    String kind,
    List<String> grants,
    boolean dynamic,
    String website,
    String privacyPolicy,
    String logo,
    List<String> redirectUris,
    Optional<List<String>> requestableScopes,
    boolean pkceRequired,
    boolean parRequired,
    boolean dpopRequired,
    String tokenAuthMethod,
    boolean confidential,
    Optional<Instant> modifiedAt) {

  private static final DateTimeFormatter DATE =
      DateTimeFormatter.ofPattern("d MMM yyyy", Locale.ENGLISH).withZone(ZoneOffset.UTC);

  public static ConsoleClient of(Client client) {
    String clientId = client.getClientIdAlias() != null ? client.getClientIdAlias() : String.valueOf(client.getClientId());
    String name = client.getClientName() != null ? client.getClientName() : clientId;
    String method = client.getTokenAuthMethod() == null ? "none" : client.getTokenAuthMethod().name().toLowerCase(Locale.ROOT);
    boolean confidential = client.getClientType() == ClientType.CONFIDENTIAL;
    String application =
        client.getGrantTypes() != null && Arrays.asList(client.getGrantTypes()).contains(GrantType.DEVICE_CODE)
                && client.getGrantTypes().length == 1
            ? "Device"
            : client.getApplicationType() != null && client.getApplicationType().name().equals("NATIVE") ? "Native app" : "Web";
    String authentication = confidential ? (method.equals("client_secret_basic") || method.equals("client_secret_post") ? "confidential" : method) : "public";
    List<String> grants =
        client.getGrantTypes() == null
            ? List.of()
            : Arrays.stream(client.getGrantTypes()).map(ConsoleClient::shortGrant).toList();
    Optional<List<String>> scopes =
        client.getExtension() != null
                && client.getExtension().isRequestableScopesEnabled()
                && client.getExtension().getRequestableScopes() != null
            ? Optional.of(List.of(client.getExtension().getRequestableScopes()))
            : Optional.empty();
    return new ConsoleClient(
        client.getClientId(),
        clientId,
        name,
        application + " (" + authentication + ")",
        grants,
        client.isDynamicallyRegistered(),
        text(client.getClientUri()),
        text(client.getPolicyUri()),
        text(client.getLogoUri()),
        client.getRedirectUris() == null ? List.of() : List.of(client.getRedirectUris()),
        scopes,
        client.isPkceRequired(),
        client.isParRequired(),
        client.isDpopRequired(),
        method,
        confidential,
        client.getModifiedAt() > 0 ? Optional.of(Instant.ofEpochMilli(client.getModifiedAt())) : Optional.empty());
  }

  public String initials() {
    return Initials.of(name);
  }

  public String registeredVia() {
    return dynamic ? "Dynamic (RFC 7591)" : "Console";
  }

  public String redirectUrisText() {
    return String.join("\n", redirectUris);
  }

  public Optional<String> modified() {
    return modifiedAt.map(DATE::format);
  }

  /** Whether the client may request {@code scope} (all scopes when not limited). */
  public boolean allows(String scope) {
    return requestableScopes.map(scopes -> scopes.contains(scope)).orElse(true);
  }

  public boolean matches(String query) {
    if (query == null || query.isBlank()) {
      return true;
    }
    String lower = query.trim().toLowerCase(Locale.ROOT);
    return name.toLowerCase(Locale.ROOT).contains(lower)
        || clientId.toLowerCase(Locale.ROOT).contains(lower)
        || String.valueOf(id).contains(lower);
  }

  private static String shortGrant(GrantType grant) {
    return switch (grant) {
      case AUTHORIZATION_CODE -> "code";
      case REFRESH_TOKEN -> "refresh";
      case CLIENT_CREDENTIALS -> "client_credentials";
      case DEVICE_CODE -> "device_code";
      case CIBA -> "ciba";
      case TOKEN_EXCHANGE -> "token_exchange";
      case JWT_BEARER -> "jwt_bearer";
      default -> grant.name().toLowerCase(Locale.ROOT);
    };
  }

  private static String text(URI uri) {
    return uri == null ? "" : uri.toString();
  }
}

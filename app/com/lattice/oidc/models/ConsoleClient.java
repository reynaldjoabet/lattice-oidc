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

  /**
   * One step of how the client gets and uses a token, with the setting that guards it. {@code tone}
   * is {@code good} (the stronger choice is on), {@code warn} (worth fixing) or {@code neutral}.
   */
  public record PathStep(String label, String setting, String note, String tone) {}

  /** The client's token flow, step by step, as the console's summary shows it. */
  public List<PathStep> tokenPath() {
    PathStep request =
        parRequired
            ? new PathStep("Pushed request", "PAR required", "Request details never pass through the browser", "good")
            : new PathStep("Request", "Sent through the browser", "Require PAR to keep request details out of the address bar", "neutral");
    PathStep signIn =
        pkceRequired
            ? new PathStep("Sign-in", "PKCE required", "A stolen code is useless on its own", "good")
            : confidential
                ? new PathStep("Sign-in", "PKCE optional", "Its secret protects the code exchange", "neutral")
                : new PathStep("Sign-in", "PKCE not required", "A public app without PKCE can have its codes stolen", "warn");
    boolean plainHttp =
        redirectUris.stream()
            .anyMatch(uri -> uri.startsWith("http://") && !uri.startsWith("http://localhost") && !uri.startsWith("http://127.0.0.1") && !uri.startsWith("http://[::1]"));
    PathStep back =
        redirectUris.isEmpty()
            ? new PathStep("Return", "No return address", "Sign-ins that return to the app will fail", grants.contains("code") ? "warn" : "neutral")
            : plainHttp
                ? new PathStep("Return", "Plain http address", "Codes can be read on the way back; use https", "warn")
                : new PathStep("Return", redirectUris.size() == 1 ? "1 exact address" : redirectUris.size() + " exact addresses", "Exact match, no wildcards", "good");
    PathStep tokenRequest =
        switch (tokenAuthMethod) {
          case "private_key_jwt" -> new PathStep("Token request", "Signed with its own key", "No shared secret to leak", "good");
          case "tls_client_auth", "self_signed_tls_client_auth" -> new PathStep("Token request", "Client certificate", "No shared secret to leak", "good");
          case "none" -> new PathStep("Token request", "No client secret", "A public app: PKCE is what protects it", "neutral");
          default -> new PathStep("Token request", "Shared secret", "A signed key (private_key_jwt) can't be copied from config", "neutral");
        };
    PathStep use =
        dpopRequired
            ? new PathStep("Using the token", "Bound to a key (DPoP)", "A stolen token can't be used elsewhere", "good")
            : new PathStep("Using the token", "Bearer token", "Not bound to a key; turn on DPoP to bind it", "neutral");
    return List.of(request, signIn, back, tokenRequest, use);
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

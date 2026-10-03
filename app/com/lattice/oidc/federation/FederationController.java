package com.lattice.oidc.federation;

import com.authlete.common.dto.FederationConfigurationRequest;
import com.authlete.common.dto.FederationConfigurationResponse;
import com.authlete.common.dto.FederationRegistrationRequest;
import com.authlete.common.dto.FederationRegistrationResponse;
import com.authlete.common.types.EntityType;
import com.lattice.oidc.authorization.AuthorizationInteraction;
import com.lattice.oidc.authorization.Pages;
import com.lattice.oidc.http.AuthleteController;
import com.lattice.oidc.http.Responses;
import com.lattice.oidc.session.Interactions;
import com.lattice.oidc.session.UserSessions;
import com.lattice.oidc.user.User;
import com.lattice.oidc.user.UserStore;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import javax.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.mvc.BodyParser;
import play.mvc.Http;
import play.mvc.Result;

/**
 * OpenID Federation endpoints and ID federation (login through external OpenID Providers).
 *
 * <ul>
 *   <li>{@code GET /.well-known/openid-federation}: the entity configuration.
 *   <li>{@code POST /api/federation/register}: explicit client registration.
 *   <li>{@code GET /api/federation/initiation/:id}, {@code GET /api/federation/callback/:id}: login
 *       with an external OpenID Provider from the authorization page.
 * </ul>
 *
 * @see <a href="https://openid.net/specs/openid-federation-1_0.html">OpenID Federation 1.0</a>
 */
public final class FederationController extends AuthleteController {

  private static final Logger LOG = LoggerFactory.getLogger(FederationController.class);
  private static final String KIND = "federation";
  private static final String AUTHZ = "authz";

  private record Pending(String federationId, String ticket, String verifier, String nonce) {}

  private final Federations federations;
  private final Interactions interactions;
  private final UserSessions sessions;
  private final UserStore users;

  @Inject
  public FederationController(
      Federations federations, Interactions interactions, UserSessions sessions, UserStore users) {
    this.federations = federations;
    this.interactions = interactions;
    this.sessions = sessions;
    this.users = users;
  }

  /**
   * Entity configuration endpoint.
   *
   * <p>An OpenID Provider that supports OpenID Federation 1.0 must provide an endpoint that returns
   * its entity configuration in JWT format. The URI of the endpoint is Entity ID + {@code
   * /.well-known/openid-federation} (or, as in RFC 8414, the host component of the Entity ID +
   * {@code /.well-known/openid-federation} + the path component of the Entity ID). The Entity ID is a
   * URL that identifies an OpenID Provider (and other entities including Relying Parties, Trust
   * Anchors and Intermediate Authorities) in the context of OpenID Federation 1.0.
   */
  public CompletionStage<Result> configuration() {
    return async(
        () -> {
          // The request to Authlete's /federation/configuration API: this server acts as an OpenID Provider
          // and as an OpenID Credential Issuer.
          FederationConfigurationResponse r =
              api()
                  .federationConfiguration(
                      new FederationConfigurationRequest()
                          .setEntityTypes(
                              new EntityType[] {
                                EntityType.OPENID_PROVIDER, EntityType.OPENID_CREDENTIAL_ISSUER
                              }));
          String content = r.getResponseContent();
          return switch (r.getAction()) {
            case OK -> Responses.of(200, content, Responses.ENTITY_STATEMENT, null);
            case NOT_FOUND -> Responses.notFound(content);
            case INTERNAL_SERVER_ERROR -> Responses.serverError(content);
            default -> throw unknownAction("/federation/configuration", r.getAction());
          };
        });
  }

  /**
   * Federation registration endpoint ("explicit" client registration).
   *
   * <p>The endpoint accepts {@code POST} requests whose {@code Content-Type} is either of the
   * following.
   * <ul>
   *   <li>{@code application/entity-statement+jwt}: the content is the entity configuration of the
   *       relying party to be registered.
   *   <li>{@code application/trust-chain+json}: the content is a JSON array of entity statements in
   *       JWT format, composing the trust chain of the relying party to be registered.
   * </ul>
   *
   * <p>On successful registration, the endpoint returns a kind of entity statement (JWT) with {@code
   * 200 OK}. The discovery document should include the {@code federation_registration_endpoint}
   * server metadata that denotes the URL of this endpoint.
   */
  @BodyParser.Of(BodyParser.TolerantText.class)
  public CompletionStage<Result> register(Http.Request request) {
    String body = request.body().asText();
    String contentType = request.contentType().orElse("");
    return async(
        () -> {
          FederationRegistrationRequest req = new FederationRegistrationRequest();
          if (contentType.equalsIgnoreCase("application/entity-statement+jwt")) {
            req.setEntityConfiguration(body);
          } else if (contentType.equalsIgnoreCase("application/trust-chain+json")) {
            req.setTrustChain(body);
          } else {
            return Responses.json(
                415,
                Responses.error(
                    "invalid_request",
                    "Content-Type must be application/entity-statement+jwt or application/trust-chain+json."));
          }
          FederationRegistrationResponse r = api().federationRegistration(req);
          String content = r.getResponseContent();
          return switch (r.getAction()) {
            case OK -> Responses.of(200, content, Responses.ENTITY_STATEMENT, null);
            case BAD_REQUEST -> Responses.badRequest(content);
            case NOT_FOUND -> Responses.notFound(content);
            case INTERNAL_SERVER_ERROR -> Responses.serverError(content);
            default -> throw unknownAction("/federation/registration", r.getAction());
          };
        });
  }

  /**
   * Starts login with an external OpenID Provider from the authorization page: redirects the browser
   * to the provider's authorization endpoint (authorization code flow with PKCE, state and nonce).
   * The pending authorization request is identified by its {@code ticket}.
   */
  public CompletionStage<Result> initiation(Http.Request request, String federationId, String ticket) {
    return async(
        () -> {
          Optional<Federation> federation = federations.get(federationId);
          if (federation.isEmpty()) {
            return Pages.message(request, 404, "Unknown provider", "No such ID federation.");
          }
          String bid = request.session().get("bid").orElse(null);
          if (interactions.get(AUTHZ, ticket, bid, AuthorizationInteraction.class).isEmpty()) {
            return Pages.message(
                request, 400, "Request expired", "Please start again from the application.");
          }
          String state = UserSessions.randomId();
          String verifier = UserSessions.randomId() + UserSessions.randomId();
          String nonce = UserSessions.randomId();
          try {
            URI location = federation.get().authenticationRequest(state, verifier, nonce);
            interactions.put(KIND, state, bid, new Pending(federationId, ticket, verifier, nonce));
            return Responses.location(location.toString());
          } catch (IOException e) {
            LOG.warn("Federation {} initiation failed: {}", federationId, e.getMessage());
            return Pages.message(
                request, 502, "Provider unavailable", "The identity provider could not be reached.");
          }
        });
  }

  /**
   * Redirection endpoint for the external OpenID Provider. Completes the code flow, validates the ID
   * token and the UserInfo response, provisions/updates the local account ({@code sub@federation}),
   * logs the user in and shows the authorization page again so that the user can authorize the
   * client.
   */
  public CompletionStage<Result> callback(Http.Request request, String federationId) {
    return async(
        () -> {
          String bid = request.session().get("bid").orElse(null);
          String state = request.queryString("state").orElse(null);
          Optional<Pending> pending = interactions.take(KIND, state, bid, Pending.class);
          Optional<Federation> federation = federations.get(federationId);
          if (pending.isEmpty()
              || federation.isEmpty()
              || !pending.get().federationId().equals(federationId)) {
            return Pages.message(
                request, 400, "Request expired", "Please start again from the application.");
          }
          Optional<AuthorizationInteraction> ix =
              interactions.get(AUTHZ, pending.get().ticket(), bid, AuthorizationInteraction.class);
          if (ix.isEmpty()) {
            return Pages.message(
                request, 400, "Request expired", "Please start again from the application.");
          }

          UserInfo userInfo;
          try {
            userInfo =
                federation
                    .get()
                    .complete(
                        URI.create(requests.requestUrl(request)),
                        state,
                        pending.get().verifier(),
                        pending.get().nonce());
          } catch (IOException e) {
            LOG.warn("Federation {} login failed: {}", federationId, e.getMessage());
            var page = ix.get().page().withError("Login with the external provider failed.");
            return Responses.of(
                502, views.html.oidc.authorization.render(page, request).body(), Responses.HTML, null);
          }

          User user = provision(federationId, userInfo);
          Map<String, String> sessionOut = new HashMap<>();
          sessions.login(user, System.currentTimeMillis() / 1000L, null, sessionOut);
          var page = ix.get().page().withLoggedInAs(Optional.of(user.displayName())).withError(null);
          interactions.put(
              AUTHZ,
              pending.get().ticket(),
              bid,
              ix.get().withPage(page).withShownSubject(user.getSubject()));
          Result result =
              Responses.of(
                  200, views.html.oidc.authorization.render(page, request).body(), Responses.HTML, null);
          return sessions.apply(result, request, sessionOut);
        });
  }

  /** Creates/updates the local account mirroring the external user ({@code sub@federation}). */
  private User provision(String federationId, UserInfo info) {
    Map<String, Object> claims = new LinkedHashMap<>(info.toJSONObject());
    claims.remove("sub");
    User user =
        new User(info.getSubject().getValue() + "@" + federationId, null, null, claims, Map.of(), List.of());
    users.save(user);
    return user;
  }
}

package com.lattice.oidc.controllers;

import com.authlete.common.dto.Client;
import com.authlete.common.dto.FederationConfigurationRequest;
import com.authlete.common.dto.FederationConfigurationResponse;
import com.authlete.common.dto.FederationRegistrationRequest;
import com.authlete.common.dto.FederationRegistrationResponse;
import com.authlete.common.types.EntityType;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.security.AuditService;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import java.io.IOException;
import java.net.URI;
import java.text.ParseException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import jakarta.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.mvc.BodyParser;
import play.mvc.Http;
import play.mvc.Result;

/**
 * OpenID Federation 1.0 endpoints of this OpenID Provider.
 *
 * <ul>
 *   <li>{@code GET /.well-known/openid-federation}: the entity configuration.
 *   <li>{@code POST /api/federation/register}: explicit client registration.
 * </ul>
 *
 * <p>Not to be confused with identity brokering (signing in with an upstream identity provider),
 * which is handled by {@link IdentityBrokerController}.
 *
 * @see <a href="https://openid.net/specs/openid-federation-1_0.html">OpenID Federation 1.0</a>
 */
public final class FederationController extends BaseController {

  private static final Logger log = LoggerFactory.getLogger(FederationController.class);

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
   * Federation registration endpoint ("explicit" client registration, OpenID Federation 1.0 §12.2).
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
   * <p>Authlete resolves the trust chain, applies the metadata policies, registers the client and
   * signs the response. On success the endpoint returns that JWT with {@code 200 OK}, served with the
   * media type its {@code typ} names: {@code application/explicit-registration-response+jwt} in the
   * final specification (§12.2.3), or {@code application/entity-statement+jwt} from an Authlete that
   * still types it as the drafts did. The URL of this endpoint goes in the Authlete service's {@code
   * federation_registration_endpoint}, which the discovery document publishes.
   */
  @BodyParser.Of(BodyParser.TolerantText.class)
  public CompletionStage<Result> register(Http.Request request) {
    String body = request.body().asText();
    String contentType = request.contentType().orElse("");
    FederationRegistrationRequest registrationRequest = new FederationRegistrationRequest();
    if (contentType.equalsIgnoreCase("application/entity-statement+jwt")) {
      registrationRequest.setEntityConfiguration(body);
    } else if (contentType.equalsIgnoreCase("application/trust-chain+json")) {
      registrationRequest.setTrustChain(body);
    } else {
      return CompletableFuture.completedFuture(
          Responses.json(
              415,
              Responses.error(
                  "invalid_request",
                  "Content-Type must be application/entity-statement+jwt or application/trust-chain+json.")));
    }
    if (body == null || body.isBlank()) {
      return CompletableFuture.completedFuture(
          Responses.badRequest(Responses.error("invalid_request", "The request body is empty.")));
    }
    return async(
        () -> {
          FederationRegistrationResponse r = api().federationRegistration(registrationRequest);
          String content = r.getResponseContent();
          return switch (r.getAction()) {
            case OK -> {
              auditRegistration(request, r.getClient());
              yield Responses.of(200, content, registrationResponseType(content), null);
            }
            case BAD_REQUEST -> Responses.badRequest(content);
            case NOT_FOUND -> Responses.notFound(content);
            case INTERNAL_SERVER_ERROR -> Responses.serverError(content);
            default -> throw unknownAction("/federation/registration", r.getAction());
          };
        });
  }

  /**
   * The media type for a registration response JWT, from its {@code typ}: the final specification's
   * {@code explicit-registration-response+jwt}, otherwise the drafts' entity statement (which is also
   * what an unreadable header falls back to: Authlete signed it, so it is served, not refused).
   */
  static String registrationResponseType(String jwt) {
    try {
      JOSEObjectType typ = JWSObject.parse(jwt).getHeader().getType();
      if (typ != null && "explicit-registration-response+jwt".equalsIgnoreCase(typ.getType())) {
        return Responses.EXPLICIT_REGISTRATION_RESPONSE;
      }
    } catch (ParseException | RuntimeException e) {
      log.warn("Federation registration response is not a readable JWS; serving it as an entity statement");
    }
    return Responses.ENTITY_STATEMENT;
  }

  /** Records the registration like any other client registration, with its federation details. */
  private void auditRegistration(Http.Request request, Client client) {
    if (client == null) {
      audit.record(request, AuditService.Event.CLIENT_REGISTERED, "via", "federation");
      return;
    }
    audit.record(
        request,
        AuditService.Event.CLIENT_REGISTERED,
        "client_id",
        client.getClientId(),
        "entity_id",
        client.getEntityId() == null ? null : client.getEntityId().toString(),
        "trust_anchor",
        client.getTrustAnchorId() == null ? null : client.getTrustAnchorId().toString(),
        "via",
        "federation");
  }
}

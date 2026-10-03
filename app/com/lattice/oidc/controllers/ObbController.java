package com.lattice.oidc.controllers;

import com.authlete.common.dto.IntrospectionRequest;
import com.authlete.common.dto.IntrospectionResponse;
import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.common.ObbSupport;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.WebException;
import com.lattice.oidc.models.Consent;
import com.lattice.oidc.stores.ConsentStore;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import javax.inject.Inject;
import play.mvc.BodyParser;
import play.mvc.Http;
import play.mvc.Result;

/**
 * Sample implementation of the Open Banking Brasil resource APIs used by the FAPI-BR conformance
 * suite.
 *
 * <ul>
 *   <li>Consents API: create, read and delete consents.
 *   <li>Accounts API ({@code accounts} scope), and its FAPI 2.0 baseline variant that expects the
 *       {@code fapi2base-accounts} scope.
 *   <li>Resources API.
 * </ul>
 *
 * Account and resource data are static sample data. Every response carries the {@code
 * x-fapi-interaction-id} header.
 */
public final class ObbController extends BaseController {

  private static final Map<String, Object> SAMPLE_ACCOUNT =
      Map.of(
          "brandName", "Lattice Bank",
          "companyCnpj", "40156018000100",
          "type", "CONTA_DEPOSITO_A_VISTA",
          "compeCode", "123",
          "branchCode", "6272",
          "number", "94088392",
          "checkDigit", "4",
          "accountId", "291e5a29-49ed-401f-a583-193caa7aceee");

  private final ConsentStore consents;
  private final LatticeConfig config;

  @Inject
  public ObbController(ConsentStore consents, LatticeConfig config) {
    this.consents = consents;
    this.config = config;
  }

  @BodyParser.Of(BodyParser.TolerantText.class)
  public CompletionStage<Result> createConsent(Http.Request request) {
    String body = request.body().asText();
    return obb(
        request,
        "Consent Create",
        "consents",
        (interactionId, info) -> {
          Map<String, Object> data = consentData(body, interactionId);
          @SuppressWarnings("unchecked")
          List<String> permissions =
              data.get("permissions") instanceof List<?> p ? (List<String>) p : List.of();
          Object expiration = data.get("expirationDateTime");
          Consent consent =
              consents.create(
                  permissions, expiration instanceof String s ? s : null, info.getClientId());
          return ObbSupport.json(201, interactionId, consentBody(consent));
        });
  }

  public CompletionStage<Result> readConsent(Http.Request request, String consentId) {
    return obb(
        request,
        "Consent Read",
        "consents",
        (interactionId, info) -> ObbSupport.json(200, interactionId, consentBody(ownedConsent(consentId, info, interactionId, "Consent Read"))));
  }

  public CompletionStage<Result> deleteConsent(Http.Request request, String consentId) {
    return obb(
        request,
        "Consent Delete",
        "consents",
        (interactionId, info) -> {
          Consent consent = ownedConsent(consentId, info, interactionId, "Consent Delete");
          if (consent.refreshToken() != null) {
            api().tokenDelete(consent.refreshToken());
          }
          consents.delete(consentId);
          return ObbSupport.json(204, interactionId, null);
        });
  }

  public CompletionStage<Result> accounts(Http.Request request) {
    return accountsFor(request, "accounts");
  }

  public CompletionStage<Result> fapi2BaseAccounts(Http.Request request) {
    return accountsFor(request, "fapi2base-accounts");
  }

  private CompletionStage<Result> accountsFor(Http.Request request, String scope) {
    return obb(
        request,
        "Accounts Read",
        scope,
        (interactionId, info) -> {
          requireConsentScope(info, interactionId, "Accounts Read");
          return ObbSupport.json(
              200,
              interactionId,
              Map.of("data", List.of(SAMPLE_ACCOUNT), "links", ObbSupport.links(), "meta", ObbSupport.meta()));
        });
  }

  public CompletionStage<Result> resources(Http.Request request) {
    return obb(
        request,
        "Resources Read",
        "resources",
        (interactionId, info) -> {
          requireConsentScope(info, interactionId, "Resources Read");
          return ObbSupport.json(
              200,
              interactionId,
              Map.of(
                  "data",
                  List.of(Map.of("resourceId", "resourceId", "type", "type", "status", "status")),
                  "links",
                  ObbSupport.links(),
                  "meta",
                  ObbSupport.meta()));
        });
  }

  private interface Handler {
    Result handle(String interactionId, IntrospectionResponse token);
  }

  private CompletionStage<Result> obb(Http.Request request, String code, String scope, Handler handler) {
    return async(
        () -> {
          if (!config.obbEnabled()) {
            return notFound();
          }
          String interactionId =
              ObbSupport.outgoingInteractionId(
                  code, Requests.header(request, ObbSupport.X_FAPI_INTERACTION_ID));
          return handler.handle(interactionId, validate(request, interactionId, code, scope));
        });
  }

  /**
   * Validates the access token, including the DPoP proof or certificate binding and the required
   * scope, by calling Authlete's /api/auth/introspection API.
   */
  private IntrospectionResponse validate(Http.Request request, String interactionId, String code, String scope) {
    IntrospectionResponse r =
        api()
            .introspection(
                new IntrospectionRequest()
                    .setToken(Requests.accessToken(request, null))
                    .setScopes(new String[] {scope})
                    .setClientCertificate(requests.clientCertificate(request))
                    .setDpop(Requests.header(request, "DPoP"))
                    .setHtm(request.method())
                    .setHtu(requests.htu(request)));
    String detail = r.getResultMessage();
    return switch (r.getAction()) {
      case OK -> r;
      case BAD_REQUEST -> throw fail(400, interactionId, code, "Bad Request", detail);
      case UNAUTHORIZED -> throw fail(401, interactionId, code, "Unauthorized", detail);
      case FORBIDDEN -> throw fail(403, interactionId, code, "Forbidden", detail);
      default -> throw fail(500, interactionId, code, "Internal Server Error", detail);
    };
  }

  private Consent ownedConsent(String consentId, IntrospectionResponse info, String interactionId, String code) {
    Optional<Consent> consent = consents.find(consentId);
    if (consent.isEmpty()) {
      throw fail(404, interactionId, code, "Not Found", "The consent ID does not exist.");
    }
    if (consent.get().clientId() != info.getClientId()) {
      throw fail(403, interactionId, code, "Forbidden", "Cannot access the consent with the access token.");
    }
    return consent.get();
  }

  private static void requireConsentScope(IntrospectionResponse info, String interactionId, String code) {
    if (ObbSupport.consentScope(info.getScopes()) == null) {
      throw fail(403, interactionId, code, "Forbidden", "The access token does not have a consent scope.");
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> consentData(String body, String interactionId) {
    try {
      Object data = Jsons.readMap(body).get("data");
      if (data instanceof Map<?, ?> m) {
        return (Map<String, Object>) m;
      }
    } catch (RuntimeException ignored) {
      // fall through
    }
    throw fail(400, interactionId, "Consent Create", "Bad Request", "The request has no valid 'data' object.");
  }

  private static Map<String, Object> consentBody(Consent c) {
    Map<String, Object> data = new java.util.LinkedHashMap<>();
    data.put("consentId", c.consentId());
    data.put("creationDateTime", c.creationDateTime());
    data.put("status", c.status());
    data.put("statusUpdateDateTime", c.statusUpdateDateTime());
    data.put("permissions", c.permissions());
    if (c.expirationDateTime() != null) {
      data.put("expirationDateTime", c.expirationDateTime());
    }
    data.put("links", ObbSupport.links());
    data.put("meta", ObbSupport.meta());
    return Map.of("data", data);
  }

  private static WebException fail(int status, String interactionId, String code, String title, String detail) {
    return new WebException(ObbSupport.error(status, interactionId, code, title, detail));
  }
}

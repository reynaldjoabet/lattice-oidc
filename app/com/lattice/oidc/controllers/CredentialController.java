package com.lattice.oidc.controllers;

import com.authlete.common.dto.CredentialBatchIssueRequest;
import com.authlete.common.dto.CredentialBatchIssueResponse;
import com.authlete.common.dto.CredentialBatchParseRequest;
import com.authlete.common.dto.CredentialBatchParseResponse;
import com.authlete.common.dto.CredentialDeferredIssueRequest;
import com.authlete.common.dto.CredentialDeferredIssueResponse;
import com.authlete.common.dto.CredentialDeferredParseRequest;
import com.authlete.common.dto.CredentialDeferredParseResponse;
import com.authlete.common.dto.CredentialIssuanceOrder;
import com.authlete.common.dto.CredentialIssuerJwksRequest;
import com.authlete.common.dto.CredentialIssuerJwksResponse;
import com.authlete.common.dto.CredentialIssuerMetadataRequest;
import com.authlete.common.dto.CredentialIssuerMetadataResponse;
import com.authlete.common.dto.CredentialJwtIssuerMetadataRequest;
import com.authlete.common.dto.CredentialJwtIssuerMetadataResponse;
import com.authlete.common.dto.CredentialNonceRequest;
import com.authlete.common.dto.CredentialNonceResponse;
import com.authlete.common.dto.CredentialOfferInfoRequest;
import com.authlete.common.dto.CredentialOfferInfoResponse;
import com.authlete.common.dto.CredentialRequestInfo;
import com.authlete.common.dto.CredentialSingleIssueRequest;
import com.authlete.common.dto.CredentialSingleIssueResponse;
import com.authlete.common.dto.CredentialSingleParseRequest;
import com.authlete.common.dto.CredentialSingleParseResponse;
import com.authlete.common.dto.IntrospectionRequest;
import com.authlete.common.dto.IntrospectionResponse;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.common.WebException;
import com.lattice.oidc.handlers.CredentialOrderHandler;
import com.lattice.oidc.handlers.CredentialRequestException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import javax.inject.Inject;
import play.mvc.BodyParser;
import play.mvc.Http;
import play.mvc.Result;

/**
 * Endpoints of OpenID for Verifiable Credential Issuance 1.0.
 *
 * <ul>
 *   <li>{@code GET /.well-known/openid-credential-issuer}: credential issuer metadata.
 *   <li>{@code GET /.well-known/jwt-issuer}, {@code /.well-known/jwt-vc-issuer}: JWT issuer
 *       metadata (SD-JWT VC).
 *   <li>{@code GET /api/vci/jwks}: the JWK Set used to sign credentials.
 *   <li>{@code POST /api/credential}, {@code /api/batch_credential}, {@code /api/deferred_credential}.
 *   <li>{@code POST /api/nonce}: the nonce endpoint.
 *   <li>{@code GET /api/offer/:identifier}: dereferences a {@code credential_offer_uri}.
 * </ul>
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OpenID for Verifiable Credential Issuance 1.0</a>
 */
public final class CredentialController extends BaseController {

  private final CredentialOrderHandler orders;

  @Inject
  public CredentialController(CredentialOrderHandler orders) {
    this.orders = orders;
  }

  /** The validated access token plus the DPoP-Nonce header to return. */
  private record Token(String value, IntrospectionResponse info, Map<String, String> headers) {}

  /**
   * Validates the access token and gets the information about it, by calling Authlete's
   * /api/auth/introspection API. The DPoP proof JWT is checked against this endpoint's URL (the
   * expected value of its {@code htu} claim), and certificate-bound tokens against the client
   * certificate.
   */
  private Token token(Http.Request request) {
    String accessToken = Requests.accessToken(request, null);
    if (accessToken == null) {
      throw new WebException(
          Responses.bearerError(400, "Bearer error=\"invalid_token\",error_description=\"An access token is required.\"", null));
    }
    IntrospectionResponse r =
        api()
            .introspection(
                new IntrospectionRequest()
                    .setToken(accessToken)
                    .setClientCertificate(requests.clientCertificate(request))
                    .setDpop(Requests.header(request, "DPoP"))
                    .setHtm("POST")
                    .setHtu(requests.htu(request)));
    Map<String, String> headers = new LinkedHashMap<>();
    if (r.getDpopNonce() != null) {
      headers.put("DPoP-Nonce", r.getDpopNonce());
    }
    String content = r.getResponseContent();
    return switch (r.getAction()) {
      case OK -> new Token(accessToken, r, headers);
      case BAD_REQUEST -> throw new WebException(Responses.bearerError(400, content, headers));
      case UNAUTHORIZED -> throw new WebException(Responses.bearerError(401, content, headers));
      case FORBIDDEN -> throw new WebException(Responses.bearerError(403, content, headers));
      default -> throw new WebException(Responses.bearerError(500, content, headers));
    };
  }

  /**
   * Prepares a credential issuance order: checks that the access token permits the requested
   * credential and builds the credential payload. With {@code deferred}, issuance is deferred and a
   * {@code transaction_id} is returned instead.
   */
  private CredentialIssuanceOrder order(
      CredentialOrderHandler.Context context, Token token, CredentialRequestInfo info, boolean deferred) {
    try {
      CredentialIssuanceOrder order = orders.toOrder(context, token.info(), info);
      if (deferred) {
        order.setIssuanceDeferred(true);
      }
      return order;
    } catch (CredentialRequestException e) {
      throw new WebException(Responses.badRequest(Responses.error(e.errorCode(), e.getMessage()), token.headers()));
    }
  }

  /** Maps parse failures shared by single/batch/deferred parse APIs. */
  private static WebException parseFailure(String action, String content, Map<String, String> headers) {
    return new WebException(
        switch (action) {
          case "BAD_REQUEST" -> Responses.badRequest(content, headers);
          case "UNAUTHORIZED" -> Responses.bearerError(401, content, headers);
          case "FORBIDDEN" -> Responses.forbidden(content, headers);
          default -> Responses.serverError(content, headers);
        });
  }

  /** Maps issue results shared by single/batch/deferred issue APIs. */
  private static Result issued(String action, String content, Map<String, String> headers) {
    return switch (action) {
      case "OK" -> Responses.ok(content, headers);
      case "OK_JWT" -> Responses.of(200, content, Responses.JWT, headers);
      case "ACCEPTED" -> Responses.json(202, content, headers);
      case "ACCEPTED_JWT" -> Responses.of(202, content, Responses.JWT, headers);
      case "BAD_REQUEST" -> Responses.badRequest(content, headers);
      case "UNAUTHORIZED" -> Responses.bearerError(401, content, headers);
      case "FORBIDDEN" -> Responses.forbidden(content, headers);
      default -> Responses.serverError(content, headers);
    };
  }

  /**
   * The credential endpoint. The {@code deferred=true} query parameter forces deferred issuance
   * (useful for testing wallets).
   */
  @BodyParser.Of(BodyParser.TolerantText.class)
  public CompletionStage<Result> credential(Http.Request request) {
    String body = request.body().asText();
    boolean deferred = Boolean.parseBoolean(request.queryString("deferred").orElse("false"));
    return async(
        () -> {
          Token token = token(request);
          // Parse the credential request with Authlete's /vci/single/parse API.
          CredentialSingleParseResponse parsed =
              api().credentialSingleParse(
                  new CredentialSingleParseRequest().setRequestContent(body).setAccessToken(token.value()));
          if (parsed.getAction() != CredentialSingleParseResponse.Action.OK) {
            throw parseFailure(parsed.getAction().name(), parsed.getResponseContent(), token.headers());
          }
          // Issue the credential with Authlete's /vci/single/issue API.
          CredentialSingleIssueResponse r =
              api().credentialSingleIssue(
                  new CredentialSingleIssueRequest()
                      .setAccessToken(token.value())
                      .setOrder(order(CredentialOrderHandler.Context.SINGLE, token, parsed.getInfo(), deferred)));
          return issued(r.getAction().name(), r.getResponseContent(), token.headers());
        });
  }

  /**
   * The batch credential endpoint.
   */
  @BodyParser.Of(BodyParser.TolerantText.class)
  public CompletionStage<Result> batch(Http.Request request) {
    String body = request.body().asText();
    boolean deferred = Boolean.parseBoolean(request.queryString("deferred").orElse("false"));
    return async(
        () -> {
          Token token = token(request);
          CredentialBatchParseResponse parsed =
              api().credentialBatchParse(
                  new CredentialBatchParseRequest().setRequestContent(body).setAccessToken(token.value()));
          if (parsed.getAction() != CredentialBatchParseResponse.Action.OK) {
            throw parseFailure(parsed.getAction().name(), parsed.getResponseContent(), token.headers());
          }
          CredentialRequestInfo[] infos = parsed.getInfo();
          CredentialIssuanceOrder[] list = new CredentialIssuanceOrder[infos.length];
          for (int i = 0; i < infos.length; i++) {
            list[i] = order(CredentialOrderHandler.Context.BATCH, token, infos[i], deferred);
          }
          CredentialBatchIssueResponse r =
              api().credentialBatchIssue(
                  new CredentialBatchIssueRequest().setAccessToken(token.value()).setOrders(list));
          return issued(r.getAction().name(), r.getResponseContent(), token.headers());
        });
  }

  /**
   * The deferred credential endpoint. If the credential is still not ready, the error {@code
   * issuance_pending} is returned.
   */
  @BodyParser.Of(BodyParser.TolerantText.class)
  public CompletionStage<Result> deferred(Http.Request request) {
    String body = request.body().asText();
    return async(
        () -> {
          Token token = token(request);
          CredentialDeferredParseResponse parsed =
              api().credentialDeferredParse(
                  new CredentialDeferredParseRequest().setRequestContent(body).setAccessToken(token.value()));
          if (parsed.getAction() != CredentialDeferredParseResponse.Action.OK) {
            throw parseFailure(parsed.getAction().name(), parsed.getResponseContent(), token.headers());
          }
          CredentialIssuanceOrder order =
              order(CredentialOrderHandler.Context.DEFERRED, token, parsed.getInfo(), false);
          if (order.isIssuanceDeferred()) {
            return Responses.badRequest(Responses.error("issuance_pending", null), token.headers());
          }
          CredentialDeferredIssueResponse r =
              api().credentialDeferredIssue(new CredentialDeferredIssueRequest().setOrder(order));
          return issued(r.getAction().name(), r.getResponseContent(), token.headers());
        });
  }

  /**
   * The nonce endpoint.
   *
   * <p>From Section 7.1. Nonce Request of OpenID for Verifiable Credential Issuance 1.0: "A request
   * for a nonce is made by sending an HTTP POST request to the URL provided in the nonce_endpoint
   * Credential Issuer Metadata parameter. The Nonce Endpoint is not a protected resource, meaning the
   * Wallet does not need to supply an access token to access it."
   */
  public CompletionStage<Result> nonce() {
    return async(
        () -> {
          CredentialNonceResponse r = api().credentialNonce(new CredentialNonceRequest().setPretty(false));
          return switch (r.getAction()) {
            case OK -> Responses.ok(r.getResponseContent());
            case NOT_FOUND -> Responses.notFound(r.getResponseContent());
            default -> Responses.serverError(r.getResponseContent());
          };
        });
  }

  /**
   * The credential issuer metadata endpoint.
   */
  public CompletionStage<Result> metadata() {
    return async(
        () -> {
          CredentialIssuerMetadataResponse r =
              api().credentialIssuerMetadata(new CredentialIssuerMetadataRequest().setPretty(true));
          return switch (r.getAction()) {
            case OK -> ok(r.getResponseContent()).as(Responses.JSON).withHeader(CACHE_CONTROL, "public, max-age=300");
            case NOT_FOUND -> Responses.notFound(r.getResponseContent());
            default -> Responses.serverError(r.getResponseContent());
          };
        });
  }

  /**
   * The JWT issuer metadata endpoint (SD-JWT VC).
   */
  public CompletionStage<Result> jwtIssuer() {
    return async(
        () -> {
          CredentialJwtIssuerMetadataResponse r =
              api().credentialJwtIssuerMetadata(new CredentialJwtIssuerMetadataRequest().setPretty(true));
          return switch (r.getAction()) {
            case OK -> ok(r.getResponseContent()).as(Responses.JSON).withHeader(CACHE_CONTROL, "public, max-age=300");
            case NOT_FOUND -> Responses.notFound(r.getResponseContent());
            default -> Responses.serverError(r.getResponseContent());
          };
        });
  }

  /**
   * The JWK Set of the credential issuer.
   */
  public CompletionStage<Result> jwks() {
    return async(
        () -> {
          CredentialIssuerJwksResponse r =
              api().credentialIssuerJwks(new CredentialIssuerJwksRequest().setPretty(false));
          return switch (r.getAction()) {
            case OK -> ok(r.getResponseContent()).as(Responses.JSON).withHeader(CACHE_CONTROL, "public, max-age=300");
            case NOT_FOUND -> Responses.notFound(r.getResponseContent());
            default -> Responses.serverError(r.getResponseContent());
          };
        });
  }

  /**
   * The credential offer endpoint: returns the credential offer referenced by a {@code
   * credential_offer_uri}.
   */
  public CompletionStage<Result> offer(String identifier) {
    return async(
        () -> {
          CredentialOfferInfoResponse r =
              api().credentialOfferInfo(new CredentialOfferInfoRequest().setIdentifier(identifier));
          String content =
              r.getInfo() != null ? r.getInfo().getCredentialOffer() : r.getResultMessage();
          return switch (r.getAction()) {
            case OK -> Responses.ok(content);
            case FORBIDDEN -> Responses.forbidden(Responses.error("forbidden", content), null);
            case NOT_FOUND -> Responses.notFound(Responses.error("not_found", content));
            default -> Responses.serverError(Responses.error("server_error", null));
          };
        });
  }
}

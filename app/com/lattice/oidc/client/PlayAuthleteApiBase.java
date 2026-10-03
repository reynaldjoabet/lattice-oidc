
package com.lattice.oidc.client;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.api.AuthleteApiException;
import com.authlete.common.api.Options;
import com.authlete.common.api.Settings;
import com.authlete.common.conf.AuthleteConfiguration;
import com.authlete.common.dto.ApiResponse;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Duration;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import play.libs.ws.WSClient;
import play.libs.ws.WSRequest;
import play.libs.ws.WSResponse;
import tools.jackson.databind.json.JsonMapper;

/**
 * Transport layer for the Authlete API on top of Play WS.
 *
 * <p>{@link AuthleteApi} is a blocking interface, so every call waits for the WS future. Callers
 * are expected to run on a dedicated blocking dispatcher, never on Play's default dispatcher.
 */
public abstract class PlayAuthleteApiBase implements AuthleteApi {

  protected interface AuthleteApiCall<TResponse> {
    TResponse call() throws Exception;
  }

  /** Signals a non-2xx HTTP response so that it can be turned into an AuthleteApiException. */
  private static final class HttpStatusException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    final transient WSResponse response;

    HttpStatusException(WSResponse response) {
      super("Authlete API responded with HTTP " + response.getStatus());
      this.response = response;
    }
  }

  private static final String JSON_UTF8 = "application/json;charset=UTF-8";

  private final String baseUrl;
  private final Settings settings;
  private final WSClient ws;
  private final JsonMapper mapper;
  private final JWK dpopJwk;
  private final JWSSigner dpopSigner;

  protected PlayAuthleteApiBase(AuthleteConfiguration configuration, WSClient ws) {
    if (configuration == null) {
      throw new IllegalArgumentException("configuration is null.");
    }
    if (ws == null) {
      throw new IllegalArgumentException("ws is null.");
    }
    String url = configuration.getBaseUrl();
    this.baseUrl = url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    this.ws = ws;
    this.mapper = AuthleteJson.mapper();
    this.settings = new Settings();

    if (configuration.getDpopKey() != null) {
      try {
        this.dpopJwk = JWK.parse(configuration.getDpopKey());
        if (dpopJwk.getAlgorithm() == null) {
          throw new IllegalArgumentException("DPoP JWK must contain an 'alg' field.");
        }
        this.dpopSigner = new DefaultJWSSignerFactory().createJWSSigner(dpopJwk);
      } catch (ParseException | JOSEException e) {
        throw new IllegalArgumentException("DPoP JWK is not valid.", e);
      }
    } else {
      this.dpopJwk = null;
      this.dpopSigner = null;
    }
  }

  @Override
  public Settings getSettings() {
    return settings;
  }

  protected boolean isDpopEnabled() {
    return dpopJwk != null;
  }

  protected <TResponse> TResponse executeApiCall(AuthleteApiCall<TResponse> apiCall)
      throws AuthleteApiException {
    try {
      return apiCall.call();
    } catch (AuthleteApiException e) {
      throw e;
    } catch (HttpStatusException e) {
      WSResponse r = e.response;
      throw new AuthleteApiException(
          e.getMessage(), e, r.getStatus(), r.getStatusText(), r.getBody(), r.getHeaders());
    } catch (Throwable t) {
      // Transport failure (connect/read error): reported without an HTTP status code.
      throw new AuthleteApiException(t.getMessage(), t);
    }
  }

  protected <TResponse> TResponse callGetApi(
      String auth,
      String path,
      Class<TResponse> responseClass,
      Map<String, Object[]> params,
      Options options) {
    WSRequest request = prepare(auth, path, "GET", options);
    if (params != null) {
      for (Map.Entry<String, Object[]> param : params.entrySet()) {
        for (Object value : param.getValue()) {
          if (value != null) {
            request = request.addQueryParameter(param.getKey(), String.valueOf(value));
          }
        }
      }
    }
    request.addHeader("Accept", "application/json");
    return read(await(request.get()), responseClass);
  }

  protected Void callDeleteApi(String auth, String path, Options options) {
    WSResponse response = await(prepare(auth, path, "DELETE", options).delete());
    ensureSuccess(response);
    return null;
  }

  protected <TResponse> TResponse callPostApi(
      String auth, String path, Object body, Class<TResponse> responseClass, Options options) {
    String json = body == null ? "{}" : mapper.writeValueAsString(body);
    WSRequest request =
        prepare(auth, path, "POST", options)
            .addHeader("Accept", "application/json")
            .setContentType(JSON_UTF8);
    return read(await(request.post(json)), responseClass);
  }

  private WSRequest prepare(String auth, String path, String method, Options options) {
    WSRequest request =
        ws.url(baseUrl + path)
            .setRequestTimeout(Duration.ofMillis(readTimeoutMillis()))
            .setFollowRedirects(false);
    if (auth != null) {
      request = request.addHeader("Authorization", auth);
    }
    if (dpopJwk != null) {
      request = request.addHeader("DPoP", createDpopProof(method, baseUrl + path));
    }
    return applyCustomHeaders(request, options);
  }

  private String createDpopProof(String method, String htu) {
    JWSHeader header =
        new JWSHeader.Builder(JWSAlgorithm.parse(dpopJwk.getAlgorithm().getName()))
            .type(new JOSEObjectType("dpop+jwt"))
            .jwk(dpopJwk.toPublicJWK())
            .build();
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .claim("htm", method)
            .claim("htu", htu)
            .jwtID(UUID.randomUUID().toString())
            .issueTime(new Date())
            .build();
    SignedJWT proof = new SignedJWT(header, claims);
    try {
      proof.sign(dpopSigner);
    } catch (JOSEException e) {
      throw new AuthleteApiException("Failed to sign the DPoP proof for the Authlete API.", e);
    }
    return proof.serialize();
  }

  private static WSRequest applyCustomHeaders(WSRequest request, Options options) {
    if (options == null || options.getHeaders() == null) {
      return request;
    }
    for (Map.Entry<String, String> e : options.getHeaders().entrySet()) {
      String key = e.getKey();
      if (key.equalsIgnoreCase("Accept")
          || key.equalsIgnoreCase("Authorization")
          || key.equalsIgnoreCase("Content-Type")) {
        continue;
      }
      request = request.addHeader(key, e.getValue());
    }
    return request;
  }

  private int readTimeoutMillis() {
    int timeout = settings.getReadTimeout();
    return timeout > 0 ? timeout : 60_000;
  }

  private WSResponse await(CompletionStage<WSResponse> stage) {
    // Play WS enforces the request timeout itself; this bound only guards against a stuck future.
    long bound = readTimeoutMillis() + Math.max(settings.getConnectionTimeout(), 0) + 5_000L;
    try {
      return stage.toCompletableFuture().get(bound, TimeUnit.MILLISECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new AuthleteApiException("Interrupted while calling the Authlete API.", e);
    } catch (ExecutionException e) {
      Throwable cause = e.getCause() != null ? e.getCause() : e;
      throw new AuthleteApiException("Authlete API call failed: " + cause.getMessage(), cause);
    } catch (TimeoutException e) {
      throw new AuthleteApiException("Authlete API call timed out.", e);
    }
  }

  private static void ensureSuccess(WSResponse response) {
    int status = response.getStatus();
    if (status < 200 || status >= 300) {
      throw new HttpStatusException(response);
    }
  }

  private <TResponse> TResponse read(WSResponse response, Class<TResponse> responseClass) {
    ensureSuccess(response);
    String body = response.getBody();
    if (responseClass == String.class) {
      return responseClass.cast(body);
    }
    TResponse value = mapper.readValue(body, responseClass);
    if (value instanceof ApiResponse apiResponse) {
      apiResponse.setResponseHeaders(new LinkedHashMap<String, List<String>>(response.getHeaders()));
    }
    return value;
  }
}

package com.lattice.oidc.common;

import com.authlete.common.dto.Pair;
import com.authlete.common.web.BasicCredentials;
import com.authlete.common.web.BearerToken;
import com.authlete.common.web.DpopToken;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import play.mvc.Http;

/** Extracts protocol inputs (parameters, credentials, certificates, URLs) from Play requests. */
@Singleton
public final class Requests {

  /** Headers set by common TLS-terminating proxies (nginx, Apache, Envoy, AWS ALB). */
  private static final List<String> SINGLE_CERT_HEADERS =
      List.of("X-Ssl-Cert", "X-Client-Cert", "X-Forwarded-Client-Cert-Pem");

  private final LatticeConfig config;

  @Inject
  public Requests(LatticeConfig config) {
    this.config = config;
  }

  /** Form parameters of the body, or an empty map when the body is not form-encoded. */
  public static Map<String, String[]> form(Http.Request request) {
    Map<String, String[]> form = request.body().asFormUrlEncoded();
    return form == null ? Map.of() : form;
  }

  public static String first(Map<String, String[]> params, String name) {
    String[] values = params.get(name);
    return values == null || values.length == 0 ? null : values[0];
  }

  /** Re-encodes parameters as application/x-www-form-urlencoded, the format Authlete expects. */
  public static String encode(Map<String, String[]> params) {
    StringBuilder sb = new StringBuilder();
    for (Map.Entry<String, String[]> e : params.entrySet()) {
      for (String value : e.getValue()) {
        if (sb.length() > 0) {
          sb.append('&');
        }
        sb.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
            .append('=')
            .append(URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8));
      }
    }
    return sb.toString();
  }

  public static Map<String, String[]> decode(String body) {
    Map<String, List<String>> decoded = new LinkedHashMap<>();
    if (body != null && !body.isEmpty()) {
      for (String pair : body.split("&")) {
        if (pair.isEmpty()) {
          continue;
        }
        int separator = pair.indexOf('=');
        String name = separator < 0 ? pair : pair.substring(0, separator);
        String value = separator < 0 ? "" : pair.substring(separator + 1);
        decoded.computeIfAbsent(URLDecoder.decode(name, StandardCharsets.UTF_8), key -> new ArrayList<>())
            .add(URLDecoder.decode(value, StandardCharsets.UTF_8));
      }
    }
    Map<String, String[]> out = new LinkedHashMap<>();
    decoded.forEach((name, value) -> out.put(name, value.toArray(String[]::new)));
    return out;
  }

  /** The raw query string, exactly as received (Authlete parses it itself). */
  public static String rawQuery(Http.Request request) {
    String uri = request.uri();
    int q = uri.indexOf('?');
    return q < 0 ? "" : uri.substring(q + 1);
  }

  public static String header(Http.Request request, String name) {
    return request.header(name).orElse(null);
  }

  public static String authorization(Http.Request request) {
    return header(request, "Authorization");
  }

  /**
   * The client ID and secret from {@code Authorization: Basic}, form-decoded as RFC 6749, section
   * 2.3.1 requires: a client sends both {@code application/x-www-form-urlencoded} before base64, so a
   * secret with {@code +}, {@code %} or {@code :} arrives as {@code %2B}, {@code %25} or {@code %3A}.
   * Without decoding, such a client could never authenticate. Secrets made of letters, digits, {@code
   * -}, {@code _}, {@code .} and {@code ~} (as Authlete generates) decode to themselves.
   */
  public static BasicCredentials basicCredentials(Http.Request request) {
    BasicCredentials raw = BasicCredentials.parse(authorization(request));
    if (raw == null) {
      return null;
    }
    return new BasicCredentials(formDecoded(raw.getUserId()), formDecoded(raw.getPassword()));
  }

  /**
   * {@code value} form-decoded, or as it is when it isn't valid form encoding (a lone {@code %}): the
   * server then rejects it as a wrong credential rather than as a malformed request.
   */
  static String formDecoded(String value) {
    if (value == null) {
      return null;
    }
    try {
      return URLDecoder.decode(value, StandardCharsets.UTF_8);
    } catch (IllegalArgumentException e) {
      return value;
    }
  }

  /** Access token from {@code Authorization: DPoP|Bearer ...}, else the given fallback. */
  public static String accessToken(Http.Request request, String fallback) {
    String auth = authorization(request);
    String token = DpopToken.parse(auth);
    if (token == null) {
      token = BearerToken.parse(auth);
    }
    return token != null ? token : fallback;
  }

  public static Pair[] headersAsPairs(Http.Request request) {
    List<Pair> pairs = new ArrayList<>();
    request
        .getHeaders()
        .asMap()
        .forEach((name, values) -> values.forEach(value -> pairs.add(new Pair(name, value))));
    return pairs.toArray(Pair[]::new);
  }

  /** scheme://host of this server as seen by clients. */
  public String baseUrl(Http.Request request) {
    return config
        .publicBaseUrl()
        .orElseGet(() -> (request.secure() ? "https" : "http") + "://" + request.host());
  }

  /** Full URL of the request (including the query), as seen by clients. */
  public String requestUrl(Http.Request request) {
    return baseUrl(request) + request.uri();
  }

  /** URL of the request without query, as used for the DPoP {@code htu} claim. */
  public String htu(Http.Request request) {
    return baseUrl(request) + request.path();
  }

  /**
   * TLS client certificate chain as PEM strings (leaf first). Taken from the TLS connection when
   * Play terminates TLS, otherwise from proxy headers if {@code lattice.mtls.trust-proxy-headers}.
   */
  public String[] clientCertificateChain(Http.Request request) {
    Optional<List<X509Certificate>> tls = request.clientCertificateChain();
    if (tls.isPresent() && !tls.get().isEmpty()) {
      List<String> pems = new ArrayList<>();
      for (X509Certificate cert : tls.get()) {
        try {
          pems.add(toPem(cert.getEncoded()));
        } catch (CertificateEncodingException e) {
          return null;
        }
      }
      return pems.toArray(String[]::new);
    }
    if (!config.trustProxyCertificateHeaders()) {
      return null;
    }
    List<String> chain = new ArrayList<>();
    String leaf = null;
    for (String name : SINGLE_CERT_HEADERS) {
      leaf = normalizePem(header(request, name));
      if (leaf != null) {
        break;
      }
    }
    if (leaf == null) {
      leaf = rfc9440(header(request, "Client-Cert"));
    }
    if (leaf == null) {
      return null;
    }
    chain.add(leaf);
    for (int i = 1; i <= 9; i++) {
      String next = normalizePem(header(request, "X-Ssl-Cert-Chain-" + i));
      if (next == null) {
        break;
      }
      chain.add(next);
    }
    return chain.toArray(String[]::new);
  }

  public String clientCertificate(Http.Request request) {
    String[] chain = clientCertificateChain(request);
    return chain == null || chain.length == 0 ? null : chain[0];
  }

  private static String normalizePem(String value) {
    if (value == null || value.isBlank() || value.equals("(null)")) {
      return null;
    }
    if (value.startsWith("-----BEGIN%20") || value.contains("%0A")) {
      return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }
    return value;
  }

  /** RFC 9440: {@code Client-Cert: :base64(DER):}. */
  private static String rfc9440(String value) {
    if (value == null) {
      return null;
    }
    String trimmed = value.trim();
    if (trimmed.length() < 3 || !trimmed.startsWith(":") || !trimmed.endsWith(":")) {
      return null;
    }
    try {
      return toPem(Base64.getDecoder().decode(trimmed.substring(1, trimmed.length() - 1)));
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  static String toPem(byte[] der) {
    return "-----BEGIN CERTIFICATE-----\n"
        + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der)
        + "\n-----END CERTIFICATE-----\n";
  }
}
